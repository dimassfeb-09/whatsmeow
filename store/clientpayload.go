// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/libsignal/ecc"

	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/proto/waWa6"
	"go.mau.fi/whatsmeow/types"
)

// WAVersionContainer is a container for a WhatsApp web version number.
type WAVersionContainer [3]uint32

// ParseVersion parses a version string (three dot-separated numbers) into a WAVersionContainer.
func ParseVersion(version string) (parsed WAVersionContainer, err error) {
	var part1, part2, part3 int
	if parts := strings.Split(version, "."); len(parts) != 3 {
		err = fmt.Errorf("'%s' doesn't contain three dot-separated parts", version)
	} else if part1, err = strconv.Atoi(parts[0]); err != nil {
		err = fmt.Errorf("first part of '%s' is not a number: %w", version, err)
	} else if part2, err = strconv.Atoi(parts[1]); err != nil {
		err = fmt.Errorf("second part of '%s' is not a number: %w", version, err)
	} else if part3, err = strconv.Atoi(parts[2]); err != nil {
		err = fmt.Errorf("third part of '%s' is not a number: %w", version, err)
	} else {
		parsed = WAVersionContainer{uint32(part1), uint32(part2), uint32(part3)}
	}
	return
}

func (vc WAVersionContainer) LessThan(other WAVersionContainer) bool {
	return vc[0] < other[0] ||
		(vc[0] == other[0] && vc[1] < other[1]) ||
		(vc[0] == other[0] && vc[1] == other[1] && vc[2] < other[2])
}

// IsZero returns true if the version is zero.
func (vc WAVersionContainer) IsZero() bool {
	return vc == [3]uint32{0, 0, 0}
}

// String returns the version number as a dot-separated string.
func (vc WAVersionContainer) String() string {
	parts := make([]string, len(vc))
	for i, part := range vc {
		parts[i] = strconv.Itoa(int(part))
	}
	return strings.Join(parts, ".")
}

// Hash returns the md5 hash of the String representation of this version.
func (vc WAVersionContainer) Hash() [16]byte {
	return md5.Sum([]byte(vc.String()))
}

func (vc WAVersionContainer) ProtoAppVersion() *waWa6.ClientPayload_UserAgent_AppVersion {
	return &waWa6.ClientPayload_UserAgent_AppVersion{
		Primary:   &vc[0],
		Secondary: &vc[1],
		Tertiary:  &vc[2],
	}
}

// waVersion is the WhatsApp web client version
var waVersion = WAVersionContainer{2, 3000, 1046691727}

// waDesktopVersion is the WhatsApp Desktop (UWP/MSIX) version extracted from the
// decompiled MSIX bundle: WhatsApp.Root_2.2634.101.0_x64.msix / AppxManifest.xml
// Identity Version="2.2634.101.0" Publisher CN=24803D75-212C-471A-BC57-9EF86AB91435
// TargetDeviceFamily MinVersion=10.0.19041.0
var waDesktopVersion = WAVersionContainer{2, 2634, 101}

// waDesktopBuildNumber is the Windows build from AppxManifest TargetDeviceFamily
const waDesktopBuildNumber = "10.0.19041"

// waVersionHash is the md5 hash of a dot-separated waVersion
var waVersionHash = waVersion.Hash()

// GetWAVersion gets the current WhatsApp web client version.
func GetWAVersion() WAVersionContainer {
	return waVersion
}

// SetWAVersion sets the current WhatsApp web client version.
//
// In general, you should keep the library up-to-date instead of using this,
// as there may be code changes that are necessary too (like protobuf schema changes).
func SetWAVersion(version WAVersionContainer) {
	if version.IsZero() {
		return
	}
	waVersion = version
	waVersionHash = version.Hash()
	BaseClientPayload.UserAgent.AppVersion = waVersion.ProtoAppVersion()
}

var BaseClientPayload = &waWa6.ClientPayload{
	UserAgent: &waWa6.ClientPayload_UserAgent{
		Platform:       waWa6.ClientPayload_UserAgent_WEB.Enum(),
		ReleaseChannel: waWa6.ClientPayload_UserAgent_RELEASE.Enum(),
		AppVersion:     waVersion.ProtoAppVersion(),
		Mcc:            proto.String("000"),
		Mnc:            proto.String("000"),
		OsVersion:      proto.String("0.1"),
		Manufacturer:   proto.String(""),
		Device:         proto.String("Desktop"),
		OsBuildNumber:  proto.String("0.1"),

		LocaleLanguageIso6391:       proto.String("en"),
		LocaleCountryIso31661Alpha2: proto.String("US"),
	},
	WebInfo: &waWa6.ClientPayload_WebInfo{
		WebSubPlatform: waWa6.ClientPayload_WebInfo_WEB_BROWSER.Enum(),
	},
	ConnectType:   waWa6.ClientPayload_WIFI_UNKNOWN.Enum(),
	ConnectReason: waWa6.ClientPayload_USER_ACTIVATED.Enum(),
}

var DeviceProps = &waCompanionReg.DeviceProps{
	Os: proto.String("whatsmeow"),
	Version: &waCompanionReg.DeviceProps_AppVersion{
		Primary:   proto.Uint32(0),
		Secondary: proto.Uint32(1),
		Tertiary:  proto.Uint32(0),
	},
	HistorySyncConfig: &waCompanionReg.DeviceProps_HistorySyncConfig{
		FullSyncDaysLimit:                        nil,
		FullSyncSizeMbLimit:                      nil,
		StorageQuotaMb:                           proto.Uint32(10240),
		InlineInitialPayloadInE2EeMsg:            proto.Bool(true),
		RecentSyncDaysLimit:                      nil,
		SupportCallLogHistory:                    proto.Bool(true),
		SupportBotUserAgentChatHistory:           proto.Bool(true),
		SupportCagReactionsAndPolls:              proto.Bool(true),
		SupportBizHostedMsg:                      proto.Bool(true),
		SupportRecentSyncChunkMessageCountTuning: proto.Bool(true),
		SupportHostedGroupMsg:                    proto.Bool(true),
		SupportFbidBotChatHistory:                proto.Bool(true),
		SupportAddOnHistorySyncMigration:         nil,
		SupportMessageAssociation:                proto.Bool(true),
		SupportGroupHistory:                      proto.Bool(true),
		OnDemandReady:                            nil,
		SupportGuestChat:                         nil,
		CompleteOnDemandReady:                    nil,
		ThumbnailSyncDaysLimit:                   proto.Uint32(60),
		InitialSyncMaxMessagesPerChat:            nil,
		SupportManusHistory:                      proto.Bool(true),
		SupportHatchHistory:                      proto.Bool(true),
	},
	PlatformType:    waCompanionReg.DeviceProps_UNKNOWN.Enum(),
	RequireFullSync: proto.Bool(false),
}

func SetOSInfo(name string, version [3]uint32) {
	DeviceProps.Os = &name
	DeviceProps.Version.Primary = &version[0]
	DeviceProps.Version.Secondary = &version[1]
	DeviceProps.Version.Tertiary = &version[2]
	BaseClientPayload.UserAgent.OsVersion = proto.String(fmt.Sprintf("%d.%d.%d", version[0], version[1], version[2]))
	BaseClientPayload.UserAgent.OsBuildNumber = BaseClientPayload.UserAgent.OsVersion
}

func (device *Device) getRegistrationPayload() *waWa6.ClientPayload {
	payload := proto.Clone(BaseClientPayload).(*waWa6.ClientPayload)
	regID := make([]byte, 4)
	binary.BigEndian.PutUint32(regID, device.RegistrationID)
	preKeyID := make([]byte, 4)
	binary.BigEndian.PutUint32(preKeyID, device.SignedPreKey.KeyID)
	deviceProps, _ := proto.Marshal(DeviceProps)
	payload.DevicePairingData = &waWa6.ClientPayload_DevicePairingRegistrationData{
		ERegid:      regID,
		EKeytype:    []byte{ecc.DjbType},
		EIdent:      device.IdentityKey.Pub[:],
		ESkeyID:     preKeyID[1:],
		ESkeyVal:    device.SignedPreKey.Pub[:],
		ESkeySig:    device.SignedPreKey.Signature[:],
		BuildHash:   waVersionHash[:],
		DeviceProps: deviceProps,
	}
	payload.Passive = proto.Bool(false)
	payload.Pull = proto.Bool(false)
	return payload
}

func (device *Device) getLoginPayload() *waWa6.ClientPayload {
	payload := proto.Clone(BaseClientPayload).(*waWa6.ClientPayload)
	payload.Username = proto.Uint64(device.ID.UserInt())
	payload.Device = proto.Uint32(uint32(device.ID.Device))
	payload.Passive = proto.Bool(true)
	payload.Pull = proto.Bool(true)
	payload.LidDbMigrated = proto.Bool(true)
	if payload.Lc == nil {
		payload.Lc = proto.Int32(1)
	}
	return payload
}

func (device *Device) GetClientPayload() *waWa6.ClientPayload {
	if device.ID != nil {
		if *device.ID == types.EmptyJID {
			panic(fmt.Errorf("GetClientPayload called with empty JID"))
		}
		return device.getLoginPayload()
	} else {
		return device.getRegistrationPayload()
	}
}

// --- Desktop parity helpers (decompiled WhatsApp Desktop 2.2634.101.0) ---
// AppxManifest: Identity 5319275A.WhatsAppDesktop Version 2.2634.101.0
// TargetDeviceFamily Windows.Desktop MinVersion 10.0.19041.0
// These helpers make whatsmeow present itself as the official UWP desktop client
// instead of WEB. Wire protocol (Noise_XX + XMPP + libsignal) is identical; only
// the ClientPayload/WebInfo/DeviceProps fingerprint changes.

var desktopModeEnabled bool

// GetDesktopVersion returns the decompiled Desktop MSIX version.
func GetDesktopVersion() WAVersionContainer { return waDesktopVersion }

// GetDesktopBuildNumber returns the Windows build from AppxManifest TargetDeviceFamily.
func GetDesktopBuildNumber() string { return waDesktopBuildNumber }

// IsDesktopMode reports whether desktop parity mode is enabled.
func IsDesktopMode() bool { return desktopModeEnabled }

// EnableDesktopMode switches global payloads to mimic WhatsApp Desktop UWP.
// Call this once before Connect()/GetQRChannel() if you want UWP fingerprint.
// Sources: AppxManifest.xml + WhatsAppNative.dll Curve25519/UWP DeviceProps.
func EnableDesktopMode() {
	waVersion = waDesktopVersion
	waVersionHash = waVersion.Hash()
	BaseClientPayload.UserAgent.Platform = waWa6.ClientPayload_UserAgent_WINDOWS.Enum()
	BaseClientPayload.UserAgent.ReleaseChannel = waWa6.ClientPayload_UserAgent_RELEASE.Enum()
	BaseClientPayload.UserAgent.AppVersion = waVersion.ProtoAppVersion()
	BaseClientPayload.UserAgent.OsVersion = proto.String(waDesktopBuildNumber)
	BaseClientPayload.UserAgent.OsBuildNumber = proto.String(waDesktopBuildNumber)
	BaseClientPayload.UserAgent.Manufacturer = proto.String("WhatsApp Inc.")
	BaseClientPayload.UserAgent.Device = proto.String("Desktop")
	BaseClientPayload.WebInfo.WebSubPlatform = waWa6.ClientPayload_WebInfo_WIN_STORE.Enum()
	DeviceProps.PlatformType = waCompanionReg.DeviceProps_UWP.Enum()
	DeviceProps.Os = proto.String("Windows")
	// DeviceProps.Version is *DeviceProps_AppVersion with Primary/Secondary/Tertiary pointers
	if DeviceProps.Version == nil {
		DeviceProps.Version = &waCompanionReg.DeviceProps_AppVersion{}
	}
	DeviceProps.Version.Primary = proto.Uint32(waDesktopVersion[0])
	DeviceProps.Version.Secondary = proto.Uint32(waDesktopVersion[1])
	DeviceProps.Version.Tertiary = proto.Uint32(waDesktopVersion[2])
	desktopModeEnabled = true
}

// DisableDesktopMode reverts to the default WEB fingerprint.
func DisableDesktopMode() {
	desktopModeEnabled = false
	// Caller should restart process or call SetWAVersion(default) to fully revert;
	// we intentionally do not auto-revert global BaseClientPayload here to avoid
	// surprising callers mid-session.
}
