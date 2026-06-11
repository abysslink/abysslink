// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Abysslink Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shell

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTranscriptLoadFixture verifies the D-35 loader against the committed
// fixture that exercises every directive: comment, <<, @delay, >>.
func TestTranscriptLoadFixture(t *testing.T) {
	tr, err := LoadTranscript(filepath.Join("testdata", "basic.transcript"))
	require.NoError(t, err)

	require.Len(t, tr.steps, 2, "fixture has two << emits")
	assert.Equal(t, "%begin 1700000000 1 0", tr.steps[0].line)
	assert.Equal(t, time.Duration(0), tr.steps[0].delay)
	assert.Equal(t, "%end 1700000000 1 0", tr.steps[1].line)
	assert.Equal(t, 10*time.Millisecond, tr.steps[1].delay, "@delay paces the NEXT emit")

	require.Len(t, tr.expectedWrites, 1)
	assert.Equal(t, "list-panes -a", tr.expectedWrites[0])
}

// TestTranscriptLoadUnknownDirective verifies a malformed directive errors
// with its 1-based line number.
func TestTranscriptLoadUnknownDirective(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.transcript")
	content := "# comment\n<< ok line\n!! bogus directive\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := LoadTranscript(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 3", "error must name the offending line number")
	assert.Contains(t, err.Error(), "!! bogus directive")
}

// TestTranscriptLoadBadDelay verifies an unparsable @delay duration errors
// with its line number.
func TestTranscriptLoadBadDelay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baddelay.transcript")
	require.NoError(t, os.WriteFile(path, []byte("@delay not-a-duration\n"), 0o600))

	_, err := LoadTranscript(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 1")
}

// TestMockRunStreamPlayback verifies an AddStream'd transcript replays its
// << lines in order onto Lines() (honoring @delay ordering), then closes the
// channel — simulating %exit / server death.
func TestMockRunStreamPlayback(t *testing.T) {
	tr, err := LoadTranscript(filepath.Join("testdata", "basic.transcript"))
	require.NoError(t, err)

	m := NewMockRunner()
	m.AddStream(tr)

	s, err := m.RunStream(context.Background(), "tmux", "-CC", "attach-session")
	require.NoError(t, err)

	var got []string
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ln, ok := <-s.Lines():
			if !ok {
				require.Equal(t, []string{
					"%begin 1700000000 1 0",
					"%end 1700000000 1 0",
				}, got, "<< lines must replay in order before the channel closes")
				assert.NoError(t, s.Wait(), "mock Wait returns nil after playback completes")
				return
			}
			assert.False(t, ln.Truncated)
			got = append(got, ln.Text)
		case <-deadline:
			t.Fatalf("playback did not complete; got %v", got)
		}
	}
}

// TestMockRunStreamStdinRecording verifies Stdin() writes are recorded,
// retrievable via StreamStdinWrites, and checkable against the transcript's
// >> directives via Verify.
func TestMockRunStreamStdinRecording(t *testing.T) {
	tr, err := LoadTranscript(filepath.Join("testdata", "basic.transcript"))
	require.NoError(t, err)

	m := NewMockRunner()
	m.AddStream(tr)
	s, err := m.RunStream(context.Background(), "tmux", "-CC", "attach-session")
	require.NoError(t, err)

	_, err = io.WriteString(s.Stdin(), "list-panes -a\n")
	require.NoError(t, err)

	writes := m.StreamStdinWrites()
	require.Equal(t, []string{"list-panes -a"}, writes)

	assert.NoError(t, tr.Verify(writes), "matching writes must verify clean")

	err = tr.Verify([]string{"kill-server"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list-panes -a", "mismatch error must name the expected write")
	assert.Contains(t, err.Error(), "kill-server", "mismatch error must name the actual write")

	// Drain playback to completion so Close reflects the scripted
	// end-of-playback disposition, not a mid-playback kill (IN-02).
	for range s.Lines() {
	}
	require.NoError(t, s.Close())
}

// TestMockRunStreamUnexpectedCall verifies RunStream with no remaining
// scripted transcript mirrors mock.go's unexpected-call idiom.
func TestMockRunStreamUnexpectedCall(t *testing.T) {
	m := NewMockRunner()
	_, err := m.RunStream(context.Background(), "tmux", "-CC")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected")
	assert.Contains(t, err.Error(), "tmux")
	assert.Contains(t, err.Error(), "-CC")
}

// TestTranscriptExitDirective verifies that "@exit <code>" is parsed by
// LoadTranscript: "@exit 1" loads without error; "@exit notanumber" returns
// a parse error that names the 1-based line number (mirroring bad-@delay).
func TestTranscriptExitDirective(t *testing.T) {
	t.Run("valid non-zero exit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "exit.transcript")
		require.NoError(t, os.WriteFile(path, []byte("@exit 1\n"), 0o600))
		tr, err := LoadTranscript(path)
		require.NoError(t, err)
		require.NotNil(t, tr)
		assert.NotNil(t, tr.ExitErr(), "@exit 1 must set a non-nil exit error")
	})

	t.Run("zero exit is nil", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "exit0.transcript")
		require.NoError(t, os.WriteFile(path, []byte("@exit 0\n"), 0o600))
		tr, err := LoadTranscript(path)
		require.NoError(t, err)
		require.NotNil(t, tr)
		assert.Nil(t, tr.ExitErr(), "@exit 0 must keep exitErr nil")
	})

	t.Run("absent directive is nil", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "noexit.transcript")
		require.NoError(t, os.WriteFile(path, []byte("<< %begin 1 2 3\n"), 0o600))
		tr, err := LoadTranscript(path)
		require.NoError(t, err)
		assert.Nil(t, tr.ExitErr(), "absent @exit directive must keep exitErr nil")
	})

	t.Run("bad code", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "badexit.transcript")
		require.NoError(t, os.WriteFile(path, []byte("# comment\n@exit notanumber\n"), 0o600))
		_, err := LoadTranscript(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "line 2", "error must name the 1-based line number")
	})
}

// TestMockRunStreamScriptedExitError verifies that a transcript with "@exit 1"
// causes Stream.Close() / Wait() to return a non-nil error; and that a
// transcript without @exit keeps the existing nil-error behavior.
func TestMockRunStreamScriptedExitError(t *testing.T) {
	t.Run("exit 1 yields non-nil error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "exit1.transcript")
		require.NoError(t, os.WriteFile(path, []byte("@exit 1\n"), 0o600))
		tr, err := LoadTranscript(path)
		require.NoError(t, err)

		m := NewMockRunner()
		m.AddStream(tr)
		s, err := m.RunStream(context.Background(), "tmux", "-CC", "attach-session")
		require.NoError(t, err, "RunStream itself must not fail — only the stream carries the exit")

		requireClosed(t, s.Lines(), 5*time.Second)
		assert.Error(t, s.Wait(), "Wait must return non-nil error for @exit 1")
	})

	t.Run("no exit directive yields nil error", func(t *testing.T) {
		tr, err := LoadTranscript(filepath.Join("testdata", "basic.transcript"))
		require.NoError(t, err)

		m := NewMockRunner()
		m.AddStream(tr)
		s, err := m.RunStream(context.Background(), "tmux", "-CC", "attach-session")
		require.NoError(t, err)

		// Drain all lines before waiting for close.
		deadline := time.After(5 * time.Second)
		for {
			select {
			case _, ok := <-s.Lines():
				if !ok {
					goto drained
				}
			case <-deadline:
				t.Fatal("basic.transcript playback did not complete")
			}
		}
	drained:
		assert.NoError(t, s.Wait(), "Wait must return nil when no @exit directive is present")
	})
}

// TestMockRunStreamCloseMidPlayback verifies Close stops emission and closes
// the channel even while a long @delay is pending.
func TestMockRunStreamCloseMidPlayback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slow.transcript")
	content := "<< first\n@delay 30s\n<< never-delivered\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	tr, err := LoadTranscript(path)
	require.NoError(t, err)

	m := NewMockRunner()
	m.AddStream(tr)
	s, err := m.RunStream(context.Background(), "tmux", "-CC")
	require.NoError(t, err)

	ln, ok := recvLine(t, s.Lines(), 5*time.Second)
	require.True(t, ok)
	assert.Equal(t, "first", ln.Text)

	// A kill mid-playback mirrors ExecRunner's disposition: the real runner
	// reports "signal: killed" from cmd.Wait, never the scripted exit (IN-02).
	err = s.Close()
	require.Error(t, err, "Close mid-playback must report the kill, not nil")
	assert.Contains(t, err.Error(), "signal: killed")
	requireClosed(t, s.Lines(), 2*time.Second)
}

// TestLoadTranscriptExitLastWins (IN-01): the last @exit directive wins —
// @exit 0 clears an earlier non-zero disposition, and a later non-zero
// overrides an earlier zero.
func TestLoadTranscriptExitLastWins(t *testing.T) {
	write := func(content string) *Transcript {
		path := filepath.Join(t.TempDir(), "t.transcript")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		tr, err := LoadTranscript(path)
		require.NoError(t, err)
		return tr
	}

	assert.NoError(t, write("@exit 1\n@exit 0\n").ExitErr(),
		"@exit 0 must clear an earlier non-zero disposition")
	assert.Error(t, write("@exit 0\n@exit 1\n").ExitErr(),
		"a later non-zero @exit must override an earlier zero")
}
