// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/sha256"
	"io"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"golang.org/x/crypto/hkdf"
)

func (cli *Client) handleCallEvent(ctx context.Context, node *waBinary.Node) {
	defer cli.maybeDeferredAck(ctx, node)()

	if len(node.GetChildren()) != 1 {
		cli.dispatchEvent(&events.UnknownCallEvent{Node: node})
		return
	}
	ag := node.AttrGetter()
	child := node.GetChildren()[0]
	cag := child.AttrGetter()
	basicMeta := types.BasicCallMeta{
		From:        ag.JID("from"),
		Timestamp:   ag.UnixTime("t"),
		CallCreator: cag.JID("call-creator"),
		CallID:      cag.String("call-id"),
		GroupJID:    cag.OptionalJIDOrEmpty("group-jid"),
	}
	if basicMeta.CallCreator.Server == types.HiddenUserServer {
		basicMeta.CallCreatorAlt = cag.OptionalJIDOrEmpty("caller_pn")
	} else {
		// This may not actually exist
		basicMeta.CallCreatorAlt = cag.OptionalJIDOrEmpty("caller_lid")
	}
	switch child.Tag {
	case "offer":
		cli.dispatchEvent(&events.CallOffer{
			BasicCallMeta: basicMeta,
			CallRemoteMeta: types.CallRemoteMeta{
				RemotePlatform: ag.String("platform"),
				RemoteVersion:  ag.String("version"),
			},
			Data: &child,
		})
	case "offer_notice":
		cli.dispatchEvent(&events.CallOfferNotice{
			BasicCallMeta: basicMeta,
			Media:         cag.String("media"),
			Type:          cag.String("type"),
			Data:          &child,
		})
	case "relaylatency":
		cli.dispatchEvent(&events.CallRelayLatency{
			BasicCallMeta: basicMeta,
			Data:          &child,
		})
	case "accept":
		cli.dispatchEvent(&events.CallAccept{
			BasicCallMeta: basicMeta,
			CallRemoteMeta: types.CallRemoteMeta{
				RemotePlatform: ag.String("platform"),
				RemoteVersion:  ag.String("version"),
			},
			Data: &child,
		})
	case "preaccept":
		cli.dispatchEvent(&events.CallPreAccept{
			BasicCallMeta: basicMeta,
			CallRemoteMeta: types.CallRemoteMeta{
				RemotePlatform: ag.String("platform"),
				RemoteVersion:  ag.String("version"),
			},
			Data: &child,
		})
	case "transport":
		cli.dispatchEvent(&events.CallTransport{
			BasicCallMeta: basicMeta,
			CallRemoteMeta: types.CallRemoteMeta{
				RemotePlatform: ag.String("platform"),
				RemoteVersion:  ag.String("version"),
			},
			Data: &child,
		})
	case "terminate":
		cli.dispatchEvent(&events.CallTerminate{
			BasicCallMeta: basicMeta,
			Reason:        cag.String("reason"),
			Data:          &child,
		})
	case "reject":
		cli.dispatchEvent(&events.CallReject{
			BasicCallMeta: basicMeta,
			Data:          &child,
		})
	default:
		cli.dispatchEvent(&events.UnknownCallEvent{Node: node})
	}
}

// RejectCall reject an incoming call.
func (cli *Client) RejectCall(ctx context.Context, callFrom types.JID, callID string) error {
	ownID := cli.getOwnID()
	if ownID.IsEmpty() {
		return ErrNotLoggedIn
	}
	ownID, callFrom = ownID.ToNonAD(), callFrom.ToNonAD()
	rejectNode := waBinary.Node{
		Tag:     "reject",
		Attrs:   waBinary.Attrs{"call-id": callID, "call-creator": callFrom, "count": "0"},
		Content: nil,
	}
	return cli.sendNode(ctx, waBinary.Node{
		Tag:     "call",
		Attrs:   waBinary.Attrs{"id": cli.GenerateMessageID(), "from": ownID, "to": callFrom},
		Content: []waBinary.Node{rejectNode},
	})
}

// SendCallOffer sends a call offer (VoIP signaling parity: Desktop
// WhatsAppNative.Voip.dll SendSignalingXmpp offer/accept). whatsmeow
// only had RejectCall; add offer/accept/preaccept/transport/terminate
// builders mirroring RejectCall so call signaling is XMPP-complete
// without requiring native WebRTC/RTP (media stays native-only).
func (cli *Client) SendCallOffer(ctx context.Context, to types.JID, callID string, data []waBinary.Node) error {
	return cli.sendCallNode(ctx, to, "offer", callID, data)
}
func (cli *Client) SendCallAccept(ctx context.Context, to types.JID, callID string, data []waBinary.Node) error {
	return cli.sendCallNode(ctx, to, "accept", callID, data)
}
func (cli *Client) SendCallPreAccept(ctx context.Context, to types.JID, callID string, data []waBinary.Node) error {
	return cli.sendCallNode(ctx, to, "preaccept", callID, data)
}
func (cli *Client) SendCallTransport(ctx context.Context, to types.JID, callID string, data []waBinary.Node) error {
	return cli.sendCallNode(ctx, to, "transport", callID, data)
}
func (cli *Client) SendCallTerminate(ctx context.Context, to types.JID, callID string, data []waBinary.Node) error {
	return cli.sendCallNode(ctx, to, "terminate", callID, data)
}
func (cli *Client) sendCallNode(ctx context.Context, to types.JID, tag, callID string, data []waBinary.Node) error {
	ownID := cli.getOwnID()
	if ownID.IsEmpty() {
		return ErrNotLoggedIn
	}
	ownID, to = ownID.ToNonAD(), to.ToNonAD()
	node := waBinary.Node{
		Tag:   tag,
		Attrs: waBinary.Attrs{"call-id": callID, "call-creator": ownID},
	}
	if len(data) > 0 {
		node.Content = data
	}
	return cli.sendNode(ctx, waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "from": ownID, "to": to},
		Content: []waBinary.Node{node},
	})
}

// DeriveCallSRTPKeys mirrors Desktop Axolotl.CallKeysFromCipherKeyV2(jid, cipherKey)
// → HkdfSha256 46 bytes: srtp[30] + p2p[16] (decompiled WhatsApp.Encryption.Axolotl).
// Portable Go (no native) — useful for SRTP/p2p derivations without C++.
func DeriveCallSRTPKeys(jid string, cipherKey []byte) (srtp, p2p []byte, err error) {
	h := hkdf.New(sha256.New, cipherKey, nil, []byte(jid))
	buf := make([]byte, 46)
	if _, err = io.ReadFull(h, buf); err != nil {
		return nil, nil, err
	}
	return buf[:30], buf[30:46], nil
}
