package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hraban/opus"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
)

// Simple JSON signaling envelope
type signalMsg struct {
	Type      string          `json:"type"`
	SDP       string          `json:"sdp,omitempty"`
	Candidate json.RawMessage `json:"candidate,omitempty"`
	Session   uint32          `json:"session,omitempty"`
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // replace in prod
}

// ----------------------------------------------------------------
// MCU mixer (simple scaffold)
// ----------------------------------------------------------------
const (
	sampleRate   = 48000
	channels     = 1
	frameMs      = 20
	frameSamples = (sampleRate * frameMs) / 1000
)

type mcuMixer struct {
	mu      sync.Mutex
	inputs  map[uint32]chan []int16
	outputs map[uint32]*webrtc.TrackLocalStaticRTP
	outst   map[uint32]*outState

	encMu sync.Mutex
	enc   *opus.Encoder

	// UDP helpers
	decs      map[uint32]*opus.Decoder                        // per-udp-source decoder cache
	udpBridge func(encoded []byte, recipients []UDPRecipient) // optional hook set by server to send mixed frames to UDP clients

	quit   chan struct{}
	ticker *time.Ticker
}

type outState struct {
	seq  uint16
	ts   uint32
	ssrc uint32
}

var mixer *mcuMixer

// UDPRecipient describes a native client that should receive mixed Opus frames.
// Encrypt must convert the raw Opus payload into the Mumble UDP payload expected by that client.
type UDPRecipient struct {
	Session uint32
	Addr    net.Addr
	Encrypt func(plain []byte) ([]byte, error) // per-client encryption (closure to client.crypt.Encrypt)
}

func StartMCUMixer() error {
	if mixer != nil {
		return nil
	}
	enc, err := opus.NewEncoder(sampleRate, channels, opus.Application(opus.AppVoIP))
	if err != nil {
		return err
	}
	m := &mcuMixer{
		inputs:  make(map[uint32]chan []int16),
		outputs: make(map[uint32]*webrtc.TrackLocalStaticRTP),
		outst:   make(map[uint32]*outState),
		enc:     enc,
		decs:    make(map[uint32]*opus.Decoder),
		quit:    make(chan struct{}),
		ticker:  time.NewTicker(time.Duration(frameMs) * time.Millisecond),
	}
	mixer = m
	go m.mixLoop()
	return nil
}

// SetUDPBridge allows server to provide a function that will be called for each mixed encoded Opus frame
// so the server can encrypt and send to native UDP clients.
func (m *mcuMixer) SetUDPBridge(f func(encoded []byte, recipients []UDPRecipient)) {
	m.mu.Lock()
	m.udpBridge = f
	m.mu.Unlock()
}

// AddUDPPacket accepts a raw encrypted UDP packet for session, decrypts it through decryptFn,
// decodes Opus -> PCM and pushes into the mixer input channel. It's non-blocking.
func (m *mcuMixer) AddUDPPacket(session uint32, encrypted []byte, decryptFn func([]byte) ([]byte, error)) {
	// decrypt outside of locks
	payload, err := decryptFn(encrypted)
	if err != nil || len(payload) == 0 {
		return
	}

	// ensure input channel exists
	m.mu.Lock()
	ch, ok := m.inputs[session]
	if !ok {
		ch = make(chan []int16, 8)
		m.inputs[session] = ch
	}
	// ensure decoder exists
	dec, ok := m.decs[session]
	if !ok {
		dec, err = opus.NewDecoder(sampleRate, channels)
		if err != nil {
			m.mu.Unlock()
			return
		}
		m.decs[session] = dec
	}
	m.mu.Unlock()

	// decode payload -> PCM
	pcm := make([]int16, frameSamples*channels)
	n, err := dec.Decode(payload, pcm)
	if err != nil {
		return
	}
	if n < len(pcm) {
		for i := n; i < len(pcm); i++ {
			pcm[i] = 0
		}
	}
	// non-blocking push to input channel (drop if full)
	select {
	case ch <- pcm:
	default:
	}
}

// BridgeToUDP encrypts and sends a mixed encoded Opus frame to recipients using the provided sendFunc.
// sendFunc should perform the actual UDP socket write: func(payload []byte, addr net.Addr) error
func (m *mcuMixer) BridgeToUDP(encoded []byte, recipients []UDPRecipient, sendFunc func([]byte, net.Addr) error) {
	for _, r := range recipients {
		encPayload, err := r.Encrypt(encoded)
		if err != nil {
			continue
		}
		_ = sendFunc(encPayload, r.Addr) // best-effort; ignore errors here or log in caller
	}
}

func (m *mcuMixer) Stop() {
	close(m.quit)
	m.ticker.Stop()
}

func (m *mcuMixer) AddOutput(session uint32, track *webrtc.TrackLocalStaticRTP, ssrc uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outputs[session] = track
	m.outst[session] = &outState{
		seq:  uint16(40000 & 0xffff),
		ts:   uint32(time.Now().UnixNano() / 1e6),
		ssrc: ssrc,
	}
}

func (m *mcuMixer) RemoveOutput(session uint32) {
	m.mu.Lock()
	delete(m.outputs, session)
	delete(m.outst, session)
	m.mu.Unlock()
}

func (m *mcuMixer) AddSource(session uint32, track *webrtc.TrackRemote) {
	dec, err := opus.NewDecoder(sampleRate, channels)
	if err != nil {
		return
	}

	ch := make(chan []int16, 8)
	m.mu.Lock()
	m.inputs[session] = ch
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.inputs, session)
			m.mu.Unlock()
			close(ch)
		}()

		for {
			pkt, _, err := track.ReadRTP()
			if err != nil {
				return
			}
			pcm := make([]int16, frameSamples*channels)
			n, err := dec.Decode(pkt.Payload, pcm)
			if err != nil {
				continue
			}
			if n < len(pcm) {
				for i := n; i < len(pcm); i++ {
					pcm[i] = 0
				}
			}
			// drop-old policy: non-blocking send
			select {
			case ch <- pcm:
			default:
			}
		}
	}()
}

func (m *mcuMixer) mixLoop() {
	for {
		select {
		case <-m.quit:
			return
		case <-m.ticker.C:
			m.mu.Lock()
			inputs := make(map[uint32]chan []int16, len(m.inputs))
			for k, v := range m.inputs {
				inputs[k] = v
			}
			outputs := make(map[uint32]*webrtc.TrackLocalStaticRTP, len(m.outputs))
			outst := make(map[uint32]*outState, len(m.outst))
			for k, v := range m.outputs {
				outputs[k] = v
				outst[k] = m.outst[k]
			}
			m.mu.Unlock()

			if len(inputs) == 0 || len(outputs) == 0 {
				continue
			}

			// Sample each input channel once (non-blocking) so we can reuse samples
			latest := make(map[uint32][]int16, len(inputs))
			for sid, ch := range inputs {
				select {
				case pcm := <-ch:
					latest[sid] = pcm
				default:
					latest[sid] = nil
				}
			}

			// For each output, mix all inputs except the output's own session
			for outSid, tr := range outputs {
				// build mixed sum
				mixed := make([]int32, frameSamples*channels)
				active := 0
				for inSid, pcm := range latest {
					if inSid == outSid {
						// skip the source's own frames for this output
						continue
					}
					if pcm == nil {
						continue
					}
					active++
					for i := 0; i < len(pcm); i++ {
						mixed[i] += int32(pcm[i])
					}
				}
				if active == 0 {
					// nothing to send to this output
					continue
				}

				// normalize / clamp
				outPCM := make([]int16, frameSamples*channels)
				for i := 0; i < len(outPCM); i++ {
					v := mixed[i] / int32(active)
					if v > 32767 {
						v = 32767
					} else if v < -32768 {
						v = -32768
					}
					outPCM[i] = int16(v)
				}

				// encode per-output (encoder is not goroutine-safe)
				encBuf := make([]byte, 4096)
				n, err := func() (int, error) {
					m.encMu.Lock()
					defer m.encMu.Unlock()
					return m.enc.Encode(outPCM, encBuf)
				}()
				if err != nil || n <= 0 {
					continue
				}
				encFrame := encBuf[:n]

				st := outst[outSid]
				if st == nil {
					continue
				}
				pkt := &rtp.Packet{
					Header: rtp.Header{
						Version:        2,
						PayloadType:    111, // ensure this matches negotiated PT
						SequenceNumber: st.seq,
						Timestamp:      st.ts,
						SSRC:           st.ssrc,
					},
					Payload: encFrame,
				}
				// best-effort write
				go func(track *webrtc.TrackLocalStaticRTP, p *rtp.Packet) {
					_ = track.WriteRTP(p)
				}(tr, pkt)

				st.seq++
				st.ts += uint32(frameSamples)
			}
		}
	}
}

// ----------------------------------------------------------------
// WebRTC signaling handler (uses mixer.AddSource/AddOutput on events)
// ----------------------------------------------------------------

// HandleWebRTCSignal upgrades the HTTP connection to websocket and performs JSON signaling.
// authFn(session) should return true only for authenticated sessions.
// sessionShouldRegister is called after PC + outTrack are created so caller can map session -> client state.
func HandleWebRTCSignal(w http.ResponseWriter, r *http.Request,
	authFn func(session uint32) bool,
	sessionShouldRegister func(session uint32),
	sessionShouldUnregister func(session uint32)) {

	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	var initial signalMsg
	if err := ws.ReadJSON(&initial); err != nil {
		// fallback to query param
		q := r.URL.Query().Get("session")
		if q == "" {
			_ = ws.WriteJSON(map[string]string{"error": "must provide session in first message or ?session="})
			return
		}
		n, _ := strconv.ParseUint(q, 10, 32)
		initial.Session = uint32(n)
	}

	session := initial.Session
	if !authFn(session) {
		_ = ws.WriteJSON(map[string]string{"error": "invalid or unauthenticated session"})
		// return
	}

	// Ensure mixer running
	_ = StartMCUMixer()

	// prepare WebRTC API (default codecs allowed)
	m := &webrtc.MediaEngine{}
	_ = m.RegisterDefaultCodecs()
	api := webrtc.NewAPI(webrtc.WithMediaEngine(m))

	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		_ = ws.WriteJSON(map[string]string{"error": "failed to create peerconnection"})
		return
	}
	defer pc.Close()

	// create outgoing track that mixer will write into
	outTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "audio", fmt.Sprintf("audio-%d", session))
	if err != nil {
		_ = ws.WriteJSON(map[string]string{"error": "failed to create outgoing track"})
		return
	}
	if _, err := pc.AddTrack(outTrack); err != nil {
		_ = ws.WriteJSON(map[string]string{"error": "failed to add track"})
		return
	}

	// register output in mixer (assign a basic ssrc)
	mixer.AddOutput(session, outTrack, uint32(1000+session))
	// notify caller (server) to map session <-> peerconnection/outTrack if desired
	if sessionShouldRegister != nil {
		sessionShouldRegister(session)
	}
	defer func() {
		mixer.RemoveOutput(session)
		if sessionShouldUnregister != nil {
			sessionShouldUnregister(session)
		}
	}()

	// OnTrack: decode incoming Opus frames and push into the mixer as a source.
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		// wire track into mixer: mixer.AddSource will spawn decoder goroutine
		mixer.AddSource(session, track)
	})

	// ICE candidates to client
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		js := map[string]interface{}{
			"type":      "ice",
			"candidate": c.ToJSON(),
			"session":   session,
		}
		_ = ws.WriteJSON(js)
	})

	// If initial message already contained an offer, handle it.
	if initial.Type == "offer" && initial.SDP != "" {
		_ = pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: initial.SDP})
		answer, err := pc.CreateAnswer(nil)
		if err == nil {
			_ = pc.SetLocalDescription(answer)
			_ = ws.WriteJSON(signalMsg{Type: "answer", SDP: answer.SDP})
		}
	}

	// read client -> server signaling messages (offer/ice)
	for {
		var mmsg signalMsg
		if err := ws.ReadJSON(&mmsg); err != nil {
			return
		}
		switch mmsg.Type {
		case "offer":
			if mmsg.SDP == "" {
				_ = ws.WriteJSON(map[string]string{"error": "missing sdp in offer"})
				continue
			}
			if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: mmsg.SDP}); err != nil {
				_ = ws.WriteJSON(map[string]string{"error": "failed to set remote descr"})
				continue
			}
			answer, err := pc.CreateAnswer(nil)
			if err != nil {
				_ = ws.WriteJSON(map[string]string{"error": "failed to create answer"})
				continue
			}
			if err := pc.SetLocalDescription(answer); err != nil {
				_ = ws.WriteJSON(map[string]string{"error": "failed to set local descr"})
				continue
			}
			_ = ws.WriteJSON(signalMsg{Type: "answer", SDP: answer.SDP})
		case "ice":
			if len(mmsg.Candidate) == 0 {
				continue
			}
			var cand webrtc.ICECandidateInit
			if err := json.Unmarshal(mmsg.Candidate, &cand); err != nil {
				continue
			}
			_ = pc.AddICECandidate(cand)
		default:
			// ignore
		}
	}
}

// AddUDPPacket is a safe exported wrapper around the mixer's AddUDPPacket.
func AddUDPPacket(session uint32, encrypted []byte, decryptFn func([]byte) ([]byte, error)) {
	if mixer == nil {
		return
	}
	mixer.AddUDPPacket(session, encrypted, decryptFn)
}

// SetUDPBridgeFunc registers a server-provided bridge function that the mixer will call
// for each mixed encoded Opus frame. The server bridge should encrypt and send packets.
func SetUDPBridgeFunc(f func(encoded []byte, recipients []UDPRecipient)) {
	if mixer == nil {
		return
	}
	mixer.SetUDPBridge(f)
}
