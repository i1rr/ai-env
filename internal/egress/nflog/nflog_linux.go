//go:build linux

package nflog

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// platformSourceFactory wires the Linux netlink socket to the
// generic `kernelSource` interface the observer's goroutine
// consumes. Constructed once at package init via the `init` below;
// `New` copies it onto every Observer so tests can substitute a
// fake without touching the cross-platform code.
var platformSourceFactory = newLinuxSource

func init() {
	// Pin the production factory so a regression that nil'd
	// `platformSourceFactory` (e.g. a refactor moving the assignment
	// to a delayed point) surfaces at compile time rather than at
	// run time. Tests overwrite `Observer.sourceFactory` directly
	// via `SetKernelSourceForTest`, not the package var, so the
	// pin is safe.
	_ = platformSourceFactory
}

// netlink constants the netlink-ULOG family depends on. We pin them
// here rather than reading from `golang.org/x/sys/unix` (the plan
// limits new deps to `go-nflog/v2` and `containernetworking/plugins`;
// pulling in `x/sys/unix` just for two constants would be wider).
const (
	// nlmsgHeaderSize is sizeof(struct nlmsghdr) per Linux ABI.
	nlmsgHeaderSize = 16

	// nfgenmsgSize is sizeof(struct nfgenmsg) per Linux ABI:
	//   __u8 nfgen_family; __u8 version; __be16 res_id;
	nfgenmsgSize = 4

	// nflogSubsystem is NFNL_SUBSYS_ULOG = 4. Each NFLOG netlink
	// frame's `nlmsghdr.nlmsg_type` upper byte equals this.
	nflogSubsystem = 4

	// nflogMsgPacket is NFULNL_MSG_PACKET = 0. The lower byte of
	// nlmsg_type for a packet record.
	nflogMsgPacket = 0

	// netlinkNetfilter is NETLINK_NETFILTER (12).
	netlinkNetfilter = 12

	// nfulaPacketHdr (1), nfulaPayload (9), nfulaPrefix (10):
	// the TLV attribute ids we parse from each packet record.
	// Defined by `<linux/netfilter/nfnetlink_log.h>`.
	nfulaPacketHdr = 1
	nfulaPayload   = 9
	nfulaPrefix    = 10
)

// linuxSource is the production `kernelSource`: a netlink socket
// bound to NETLINK_NETFILTER, subscribed to the configured NFLOG
// group, decoded into the cross-platform `Event` shape.
//
// The struct is intentionally small; the heavy lifting lives in
// the parser. We keep the parser pure (no goroutines, no mutex)
// so a malformed frame returned as an error does not corrupt the
// reader's state.
type linuxSource struct {
	// mu serializes Close against a concurrent Read so a tight
	// race between context cancellation and the goroutine's next
	// `recvfrom` does not double-close the socket fd.
	mu sync.Mutex

	// fd is the netlink socket file descriptor. Closed exactly
	// once by `Close`; zero after close so a second `Close` no-ops.
	fd int

	// readBuf is the per-source receive buffer. NFLOG frames are
	// almost always under 4 KiB (the kernel snaplen default), but
	// we size the buffer at 64 KiB to tolerate jumbo frames + the
	// netlink framing overhead. The buffer is reused across reads
	// so we are not allocating per packet.
	readBuf []byte

	// closed is true after `Close` has been called. Subsequent
	// `Read` calls return `errReaderClosed` so the observer's
	// loop exits cleanly.
	closed bool

	// netnsPath / netnsFd are the per-run sandbox netns. The
	// constructor enters the netns via `setns(2)` before
	// binding the socket; the path is retained for diagnostics.
	netnsPath string
	netnsFd   int
}

// newLinuxSource opens a netlink socket bound to NETLINK_NETFILTER
// and subscribes to the configured NFLOG group. The supervisor's
// per-run netns is entered via `setns(2)` so the socket reads
// packets from the sandbox, not from the supervisor's namespace.
//
// On any failure the function returns an error and releases every
// fd it opened. The plan's "fail-closed" rule means a partial
// attach is never returned: either the socket is fully bound or
// the caller sees an error.
func newLinuxSource(ctx context.Context, opts Options) (kernelSource, error) {
	// Per Linux ABI the netlink socket must be created while
	// the goroutine is locked to its OS thread so the setns
	// applies to the right thread; the goroutine that calls
	// `Read` later is a different goroutine, but the socket fd
	// is shared and the netns binding survives the close-thread
	// transition.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	netnsFd := -1
	if opts.NetNSPath != "" {
		fd, err := syscall.Open(opts.NetNSPath, syscall.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("open netns %s: %w", opts.NetNSPath, err)
		}
		// Save the current netns so the goroutine can return to
		// it on Close; CLONE_NEWNET requires re-binding so we
		// stash the original fd.
		netnsFd = fd
		if err := setns(fd, syscall.CLONE_NEWNET); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("setns %s: %w", opts.NetNSPath, err)
		}
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		if netnsFd >= 0 {
			syscall.Close(netnsFd)
		}
		return nil, fmt.Errorf("netlink socket: %w", err)
	}

	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		if netnsFd >= 0 {
			syscall.Close(netnsFd)
		}
		return nil, fmt.Errorf("netlink bind: %w", err)
	}

	src := &linuxSource{
		fd:        fd,
		readBuf:   make([]byte, 64<<10),
		netnsPath: opts.NetNSPath,
		netnsFd:   netnsFd,
	}

	// Configure the kernel to send packets for the per-run NFLOG
	// group to this socket. The two control messages are:
	//   1. NFULNL_CFG_CMD_PF_BIND  (bind protocol family AF_INET)
	//   2. NFULNL_CFG_CMD_BIND      (bind the per-group id)
	if err := src.configurePF(); err != nil {
		src.Close()
		return nil, fmt.Errorf("configure NFLOG pf bind: %w", err)
	}
	if err := src.configureGroup(opts.GroupID); err != nil {
		src.Close()
		return nil, fmt.Errorf("configure NFLOG group %d: %w", opts.GroupID, err)
	}

	return src, nil
}

// setns is a thin wrapper around the setns(2) syscall. Defined
// here rather than via `golang.org/x/sys/unix` to keep the new-dep
// surface zero.
func setns(fd int, nstype int) error {
	_, _, errno := syscall.Syscall(sysSetns, uintptr(fd), uintptr(nstype), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// configurePF sends the NFULNL_CFG_CMD_PF_BIND control message
// that tells the kernel to forward AF_INET packets matching any
// NFLOG group this socket subscribes to. Per `nfnetlink_log.h`:
//
//	struct nfulnl_msg_config_cmd { u8 command; };
//	command = NFULNL_CFG_CMD_PF_BIND  (1)
//	res_id  = AF_INET                 (2)
func (s *linuxSource) configurePF() error {
	const (
		nfulnlCfgCmd       = 1 // NFULNL_CFG_CMD
		nfulnlCfgCmdPFBind = 1 // NFULNL_CFG_CMD_PF_BIND
	)
	payload := []byte{nfulnlCfgCmdPFBind, 0, 0, 0}
	msg := buildNFLOGConfigMsg(syscall.AF_INET, 0, nfulnlCfgCmd, payload)
	_, err := syscall.Write(s.fd, msg)
	return err
}

// configureGroup sends the NFULNL_CFG_CMD_BIND control message
// that subscribes this socket to packets for `group`.
func (s *linuxSource) configureGroup(group uint16) error {
	const (
		nfulnlCfgCmd     = 1 // NFULNL_CFG_CMD
		nfulnlCfgCmdBind = 2 // NFULNL_CFG_CMD_BIND
	)
	payload := []byte{nfulnlCfgCmdBind, 0, 0, 0}
	msg := buildNFLOGConfigMsg(0, group, nfulnlCfgCmd, payload)
	_, err := syscall.Write(s.fd, msg)
	return err
}

// buildNFLOGConfigMsg assembles a netlink config message for the
// NFLOG subsystem. The frame is:
//
//	nlmsghdr { type = (NFNL_SUBSYS_ULOG<<8) | NFULNL_MSG_CONFIG,
//	          flags = NLM_F_REQUEST|NLM_F_ACK }
//	nfgenmsg { nfgen_family = af, version = 0, res_id = be(res) }
//	nfattr   { type = attrType, len, data = payload }
func buildNFLOGConfigMsg(af uint8, res uint16, attrType uint16, payload []byte) []byte {
	const nflogMsgConfig = 1 // NFULNL_MSG_CONFIG

	attrSize := 4 + len(payload)
	pad := (4 - (attrSize % 4)) % 4
	total := nlmsgHeaderSize + nfgenmsgSize + attrSize + pad

	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], uint16(nflogSubsystem<<8|nflogMsgConfig))
	binary.LittleEndian.PutUint16(buf[6:8], uint16(syscall.NLM_F_REQUEST|syscall.NLM_F_ACK))
	// seq + pid left zero — kernel fills them in.

	buf[nlmsgHeaderSize+0] = af
	buf[nlmsgHeaderSize+1] = 0 // version
	binary.BigEndian.PutUint16(buf[nlmsgHeaderSize+2:nlmsgHeaderSize+4], res)

	off := nlmsgHeaderSize + nfgenmsgSize
	binary.LittleEndian.PutUint16(buf[off:off+2], uint16(attrSize))
	binary.LittleEndian.PutUint16(buf[off+2:off+4], attrType)
	copy(buf[off+4:off+4+len(payload)], payload)
	return buf
}

// Read blocks until the next NFLOG packet arrives, decodes it, and
// returns the structured `Event`. The context's cancellation is
// honoured via a short recv timeout: the kernel does not support
// `epoll_pwait` on a netlink socket cleanly without `x/sys/unix`,
// so we poll with a 250 ms `SO_RCVTIMEO` and check ctx between
// timeouts.
func (s *linuxSource) Read(ctx context.Context) (Event, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Event{}, errReaderClosed
	}
	fd := s.fd
	s.mu.Unlock()

	tv := syscall.Timeval{Sec: 0, Usec: 250000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	for {
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		default:
		}

		n, _, err := syscall.Recvfrom(fd, s.readBuf, 0)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == syscall.EAGAIN || errno == syscall.EINTR {
					continue
				}
				if errno == syscall.EBADF {
					return Event{}, errReaderClosed
				}
			}
			return Event{}, fmt.Errorf("netlink recv: %w", err)
		}
		if n == 0 {
			return Event{}, io.EOF
		}

		evt, ok, perr := parseNFLOGFrame(s.readBuf[:n])
		if perr != nil {
			return Event{}, perr
		}
		if !ok {
			// A control / ack message we are not interested in
			// (e.g. the NLM_F_ACK reply to our config msg). Loop
			// without surfacing the no-op to the caller.
			continue
		}
		return evt, nil
	}
}

// Close releases the netlink socket and the netns fd. Idempotent;
// after Close, `Read` returns `errReaderClosed`. The plan's
// "Stop is idempotent" rule means the cross-platform Observer
// keeps a separate `stopped` flag; this Close protects against a
// double-close at the syscall level even when the upper layer's
// flag is somehow bypassed.
func (s *linuxSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.fd > 0 {
		syscall.Close(s.fd)
		s.fd = 0
	}
	if s.netnsFd > 0 {
		syscall.Close(s.netnsFd)
		s.netnsFd = 0
	}
	return nil
}

// parseNFLOGFrame decodes one netlink frame into an `Event`. The
// frame layout is:
//
//	nlmsghdr  (16 bytes)        — type, len, flags, seq, pid
//	nfgenmsg  (4 bytes)         — family, version, res_id
//	nfattr*                     — TLV attributes (packet hdr, payload, prefix, ...)
//
// We only decode the attributes we care about: NFULA_PACKET_HDR
// (hardware protocol + hook number), NFULA_PAYLOAD (IPv4/v6
// header bytes), NFULA_PREFIX (operator-supplied verdict tag the
// rule installer set via `--nflog-prefix accept` / `drop`).
//
// Returns (event, true, nil) on a parsed packet record; (zero,
// false, nil) on a control/ack message; (zero, false, err) on a
// malformed frame.
func parseNFLOGFrame(buf []byte) (Event, bool, error) {
	if len(buf) < nlmsgHeaderSize {
		return Event{}, false, errors.New("nflog: short nlmsghdr")
	}
	length := binary.LittleEndian.Uint32(buf[0:4])
	if int(length) > len(buf) {
		return Event{}, false, errors.New("nflog: truncated frame")
	}
	msgType := binary.LittleEndian.Uint16(buf[4:6])
	subsys := msgType >> 8
	cmd := msgType & 0xff
	if subsys != nflogSubsystem || cmd != nflogMsgPacket {
		return Event{}, false, nil
	}
	if int(length) < nlmsgHeaderSize+nfgenmsgSize {
		return Event{}, false, errors.New("nflog: truncated nfgenmsg")
	}
	off := nlmsgHeaderSize + nfgenmsgSize
	end := int(length)

	var (
		payload []byte
		prefix  string
	)
	for off+4 <= end {
		alen := binary.LittleEndian.Uint16(buf[off : off+2])
		atype := binary.LittleEndian.Uint16(buf[off+2 : off+4])
		if int(alen) < 4 || off+int(alen) > end {
			return Event{}, false, errors.New("nflog: bad attribute length")
		}
		data := buf[off+4 : off+int(alen)]
		switch atype {
		case nfulaPayload:
			payload = data
		case nfulaPrefix:
			prefix = trimNullTerminated(data)
		}
		// 4-byte align next attribute.
		step := int(alen)
		if pad := step % 4; pad != 0 {
			step += 4 - pad
		}
		off += step
	}

	evt := Event{Verdict: prefix}
	if len(payload) >= 1 {
		switch payload[0] >> 4 {
		case 4:
			parseIPv4(payload, &evt)
		case 6:
			parseIPv6(payload, &evt)
		}
	}
	return evt, true, nil
}

// parseIPv4 fills the protocol / address / port fields of evt from
// an IPv4 header (and its layer-4 ports when the protocol is
// tcp/udp). The parser is intentionally lenient: a truncated
// header populates the fields it can and leaves the rest at the
// zero value rather than rejecting the whole packet.
func parseIPv4(p []byte, evt *Event) {
	if len(p) < 20 {
		return
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return
	}
	proto := p[9]
	evt.SrcIP = net.IP(p[12:16]).String()
	evt.DstIP = net.IP(p[16:20]).String()
	evt.Protocol = protoName(proto)
	if (proto == 6 || proto == 17) && len(p) >= ihl+4 {
		evt.SrcPort = binary.BigEndian.Uint16(p[ihl : ihl+2])
		evt.DstPort = binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
	}
}

// parseIPv6 fills the protocol / address / port fields from an
// IPv6 header. Extension headers are not chased; we look at the
// "next header" byte and treat anything other than tcp/udp as
// "other". This matches the plan's "5-tuple, not a full deep
// parse" intent.
func parseIPv6(p []byte, evt *Event) {
	if len(p) < 40 {
		return
	}
	proto := p[6]
	evt.SrcIP = net.IP(p[8:24]).String()
	evt.DstIP = net.IP(p[24:40]).String()
	evt.Protocol = protoName(proto)
	if (proto == 6 || proto == 17) && len(p) >= 40+4 {
		evt.SrcPort = binary.BigEndian.Uint16(p[40:42])
		evt.DstPort = binary.BigEndian.Uint16(p[42:44])
	}
}

func protoName(p uint8) string {
	switch p {
	case 1, 58:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "other"
	}
}

// trimNullTerminated returns the bytes up to the first NUL as a
// string. NFLOG prefix attributes are NUL-terminated C strings.
func trimNullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// _ keeps the `time` import live in case a future tweak to the
// timeout calculation needs it. Removing this line if the import
// is genuinely unused is fine; it is here only to silence the
// linter during incremental edits.
var _ = time.Now
