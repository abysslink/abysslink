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

// Package daemon implements abysslinkd: a Unix-socket notify endpoint plus a
// watcher supervisor. The socket lets any local program fire a phone
// notification without paying process-startup cost, and the watchers turn
// "a tmux pane has been waiting for input" into a notification. The package
// depends only on a Notifier interface (not on the notify module) so it does
// not import its own consumer.
package daemon
