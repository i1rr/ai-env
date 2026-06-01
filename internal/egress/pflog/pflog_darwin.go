//go:build darwin

package pflog

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// platformSourceFactory wires the macOS BPF surface to the
// observer's `kernelSource` interface. Reassigned by tests to
// substitute a fake source without touching real BPF; production
// code path is the `newDarwinSource` factory below.
var platformSourceFactory = newDarwinSource

// DLT_PFLOG is the BPF link layer type for the pflog interface.
// Defined by `<net/bpf.h>` on macOS as 117. We pin the constant
// here rather than reading it from `golang.org/x/sys/unix` to
// keep the new-dep surface zero (plan locks new deps to the two
// modules listed in §"Tech stack").
const dltPFLOG = 117

// BPF ioctl numbers (per `<net/bpf.h>` on macOS). The constants
// are encoded via _IOW / _IOR macros; we pre-compute the values
// here so the package does not need to recreate the macro.
//
// The numbers were taken from `xnu`'s `bpf.h`:
//
//	#define BIOCGBLEN _IOR('B',102, u_int)
//	#define BIOCSETIF _IOW('B',108, struct ifreq)
//	#define BIOCIMMEDIATE _IOW('B',112, u_int)
//	#define BIOCSBLEN _IOWR('B',102, u_int)
const (
	biocgblen     = 0x40044266 // _IOR('B', 102, u_int)
	biocsetif     = 0x8020426c // _IOW('B', 108, ifreq[32])
	biocimmediate = 0x80044270 // _IOW('B', 112, u_int)
	biocsblen     = 0xc0044266 // _IOWR('B', 102, u_int)
)

// darwinSource is the production kernelSource: a BPF fd bound to
// the pflog0 interface, with a per-source read buffer sized to
// the kernel's BPF_BLEN.
type darwinSource struct {
	mu sync.Mutex

	fd      int
	closed  bool
	device  string
	readBuf []byte

	// pendingFrames is the queue of decoded BPF blocks left over
	// from a single recv: BPF returns multiple records per read
	// when the kernel batches packets, so the parser splits them
	// into individual frames the upper-loop consumes one at a
	// time.
	pendingFrames [][]byte
}

// newDarwinSource opens `/dev/bpf<n>` (probing N=0..255 until one
// succeeds), binds it to the configured pflog device, and
// configures immediate-mode reads so the goroutine sees packets
// as they arrive rather than batched.
func newDarwinSource(ctx context.Context, opts Options) (kernelSource, error) {
	fd, err := openBPF()
	if err != nil {
		return nil, fmt.Errorf("open bpf: %w", err)
	}

	// Force immediate-mode reads so a low-traffic run does not
	// stall in the kernel's batch buffer.
	one := uint32(1)
	if err := ioctlSetInt(fd, biocimmediate, &one); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("BIOCIMMEDIATE: %w", err)
	}

	// Request a 64 KiB buffer; the kernel may downsize.
	blen := uint32(64 << 10)
	if err := ioctlSetInt(fd, biocsblen, &blen); err != nil {
		// non-fatal: continue with the kernel default.
	}
	gotBlen := uint32(0)
	_ = ioctlGetInt(fd, biocgblen, &gotBlen)
	if gotBlen == 0 {
		gotBlen = 4096
	}

	// Bind to the pflog device.
	if err := bindBPF(fd, opts.Device); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("BIOCSETIF %s: %w", opts.Device, err)
	}

	return &darwinSource{
		fd:      fd,
		device:  opts.Device,
		readBuf: make([]byte, gotBlen),
	}, nil
}

// openBPF scans /dev/bpf0../dev/bpf255 looking for the first
// device the calling user can open RW. macOS allocates BPF
// devices on demand; the well-known idiom is to scan until one
// succeeds.
func openBPF() (int, error) {
	var firstErr error
	for i := 0; i < 256; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
		if err == nil {
			return fd, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no /dev/bpfN device available")
	}
	return -1, firstErr
}

// bindBPF performs the BIOCSETIF ioctl, binding the BPF fd to the
// named interface. The struct ifreq layout on macOS is 32 bytes
// (16 for ifr_name, 16 for the union).
func bindBPF(fd int, device string) error {
	if len(device) >= 16 {
		return fmt.Errorf("device name %q too long", device)
	}
	var ifr [32]byte
	copy(ifr[:], device)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(biocsetif), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

// ioctlSetInt performs an _IOW ioctl carrying a single u_int
// argument.
func ioctlSetInt(fd int, op uintptr, v *uint32) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), op, uintptr(unsafe.Pointer(v)))
	if errno != 0 {
		return errno
	}
	return nil
}

// ioctlGetInt performs an _IOR ioctl reading a single u_int
// argument.
func ioctlGetInt(fd int, op uintptr, v *uint32) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), op, uintptr(unsafe.Pointer(v)))
	if errno != 0 {
		return errno
	}
	return nil
}

// Read blocks until the next pflog frame arrives, decodes it,
// and returns the structured `Event`. BPF reads may contain
// multiple records per syscall (see `bpf_hdr` framing); the
// source maintains a `pendingFrames` queue so the caller sees
// one record per `Read`.
func (s *darwinSource) Read(ctx context.Context) (Event, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Event{}, errReaderClosed
	}
	fd := s.fd
	s.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		default:
		}

		s.mu.Lock()
		if len(s.pendingFrames) > 0 {
			next := s.pendingFrames[0]
			s.pendingFrames = s.pendingFrames[1:]
			s.mu.Unlock()
			evt, ok, perr := decodePFLOGFrame(next)
			if perr != nil {
				return Event{}, perr
			}
			if !ok {
				continue
			}
			return evt, nil
		}
		s.mu.Unlock()

		// Set a short read timeout so we re-check ctx between
		// recv calls. BPF supports SO_RCVTIMEO via the standard
		// socket option path.
		tv := syscall.Timeval{Sec: 0, Usec: 250000}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, err := syscall.Read(fd, s.readBuf)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == syscall.EAGAIN || errno == syscall.EINTR {
					continue
				}
				if errno == syscall.EBADF {
					return Event{}, errReaderClosed
				}
			}
			return Event{}, fmt.Errorf("bpf read: %w", err)
		}
		if n == 0 {
			return Event{}, io.EOF
		}

		frames, perr := splitBPFBlock(s.readBuf[:n])
		if perr != nil {
			return Event{}, perr
		}
		s.mu.Lock()
		s.pendingFrames = append(s.pendingFrames, frames...)
		s.mu.Unlock()
	}
}

// Close releases the BPF fd. Idempotent.
func (s *darwinSource) Close() error {
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
	return nil
}

// bpf_hdr (per macOS `<net/bpf.h>`, BPF_ALIGNMENT = 4):
//
//	struct bpf_hdr {
//	    struct BPF_TIMEVAL bh_tstamp; // 8 bytes
//	    bpf_u_int32 bh_caplen;        // 4
//	    bpf_u_int32 bh_datalen;       // 4
//	    u_short bh_hdrlen;            // 2
//	};
//
// The header is followed by bh_caplen bytes of captured data;
// each record is aligned to 4 bytes.
const bpfAlignment = 4

// splitBPFBlock walks a BPF read block, returning one slice per
// captured frame (the DLT_PFLOG-encapsulated payload). The
// function does not interpret the frame contents; the caller
// passes each frame to `decodePFLOGFrame` for that.
func splitBPFBlock(block []byte) ([][]byte, error) {
	var out [][]byte
	off := 0
	for off+18 <= len(block) {
		caplen := binary.LittleEndian.Uint32(block[off+8 : off+12])
		hdrlen := binary.LittleEndian.Uint16(block[off+16 : off+18])
		if int(hdrlen) < 18 || off+int(hdrlen)+int(caplen) > len(block) {
			return out, errors.New("pflog: truncated bpf header")
		}
		start := off + int(hdrlen)
		end := start + int(caplen)
		out = append(out, block[start:end])
		// 4-byte align next record.
		step := int(hdrlen) + int(caplen)
		if pad := step % bpfAlignment; pad != 0 {
			step += bpfAlignment - pad
		}
		off += step
	}
	return out, nil
}

// pflog header layout (per `<net/if_pflog.h>` on macOS):
//
//	u_int8_t length;            // 1
//	sa_family_t af;             // 1 (8-bit on macOS pflog)
//	u_int8_t action;            // 1 (PF_PASS / PF_DROP / PF_SCRUB / ...)
//	u_int8_t reason;            // 1
//	char ifname[IFNAMSIZ];      // 16
//	char ruleset[PF_RULESET_NAME_SIZE]; // 16
//	u_int32_t rulenr;           // 4
//	u_int32_t subrulenr;        // 4
//	u_int8_t dir;               // 1
//	u_int8_t pad[3];            // 3
//
// Total header length is 48 bytes; the payload follows immediately.
const pflogHeaderLen = 48

// decodePFLOGFrame decodes one DLT_PFLOG frame: the per-pflog
// header followed by the captured IP packet. Returns (event,
// true, nil) on a parsed packet; (zero, false, nil) on a frame
// the parser deliberately ignored; (zero, false, err) on a
// malformed frame.
func decodePFLOGFrame(frame []byte) (Event, bool, error) {
	if len(frame) < pflogHeaderLen {
		return Event{}, false, errors.New("pflog: short pflog header")
	}
	af := frame[1]
	action := frame[2]
	payload := frame[pflogHeaderLen:]

	evt := Event{Verdict: pfActionToken(action)}
	switch af {
	case syscall.AF_INET:
		parseIPv4(payload, &evt)
	case syscall.AF_INET6:
		parseIPv6(payload, &evt)
	default:
		evt.Protocol = "other"
	}
	return evt, true, nil
}

// pfActionToken maps the pf action byte (PF_PASS / PF_DROP /
// ...) to the canonical string the supervisor's
// `outbound_blocked` / `outbound_allowed` event mapping expects.
// Values per `<net/pfvar.h>`.
func pfActionToken(action uint8) string {
	switch action {
	case 0:
		return "pass"
	case 1:
		return "drop"
	case 2:
		return "scrub"
	case 4:
		return "nat"
	case 7:
		return "rdr"
	default:
		return "other"
	}
}

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

var _ = time.Now
