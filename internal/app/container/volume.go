// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

func GenVolumeName(appId types.AppId, dirName string) VolumeName {
	dirHash := sha256.Sum256([]byte(dirName))
	hashHex := hex.EncodeToString(dirHash[:])
	return VolumeName(fmt.Sprintf("clv-%s-%s", appId, strings.ToLower(hashHex)))
}

func (c ContainerCommand) VolumeExists(name VolumeName) bool {
	c.Debug().Msgf("Checking volume exists %s", name)
	cmd := exec.Command(c.config.ContainerCommand, "volume", "inspect", string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.Debug().Msgf("volume exists check failed %s %s %s", name, err, output)
	}
	c.Debug().Msgf("volume exists %s %t", name, err == nil)
	return err == nil
}

func (c ContainerCommand) VolumeCreate(name VolumeName) error {
	c.Debug().Msgf("Creating volume %s", name)
	cmd := exec.Command(c.config.ContainerCommand, "volume", "create", string(name))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error creating volume %s: %w %s", name, err, output)
	}
	return nil
}
