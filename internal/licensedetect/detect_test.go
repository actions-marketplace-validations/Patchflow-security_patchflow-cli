package licensedetect

import (
	"testing"
)

func TestDetect_MIT(t *testing.T) {
	content := `MIT License

Copyright (c) 2024 Test Author

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

	match := Detect(content)
	if match == nil {
		t.Fatal("expected MIT match, got nil")
	}
	if match.SPDXID != "MIT" {
		t.Errorf("expected MIT, got %s (confidence: %.2f)", match.SPDXID, match.Confidence)
	}
	if match.Confidence < 0.5 {
		t.Errorf("confidence too low: %.2f", match.Confidence)
	}
}

func TestDetect_Apache2(t *testing.T) {
	content := `Apache License
Version 2.0, January 2004

Copyright 2024 Test Author

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.`

	match := Detect(content)
	if match == nil {
		t.Fatal("expected Apache-2.0 match, got nil")
	}
	if match.SPDXID != "Apache-2.0" {
		t.Errorf("expected Apache-2.0, got %s (confidence: %.2f)", match.SPDXID, match.Confidence)
	}
}

func TestDetect_BSD3(t *testing.T) {
	content := `Copyright (c) 2024 Test Author. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`

	match := Detect(content)
	if match == nil {
		t.Fatal("expected BSD-3-Clause match, got nil")
	}
	if match.SPDXID != "BSD-3-Clause" {
		t.Errorf("expected BSD-3-Clause, got %s (confidence: %.2f)", match.SPDXID, match.Confidence)
	}
}

func TestDetect_ISC(t *testing.T) {
	content := `ISC License

Copyright (c) 2024 Test Author

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.`

	match := Detect(content)
	if match == nil {
		t.Fatal("expected ISC match, got nil")
	}
	if match.SPDXID != "ISC" {
		t.Errorf("expected ISC, got %s (confidence: %.2f)", match.SPDXID, match.Confidence)
	}
}

func TestDetect_GPL3(t *testing.T) {
	content := `GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Copyright (C) 2007 Free Software Foundation, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.`

	match := Detect(content)
	if match == nil {
		t.Fatal("expected GPL-3.0 match, got nil")
	}
	if match.SPDXID != "GPL-3.0" {
		t.Errorf("expected GPL-3.0, got %s (confidence: %.2f)", match.SPDXID, match.Confidence)
	}
}

func TestDetect_MPL2(t *testing.T) {
	content := `Mozilla Public License Version 2.0
==================================

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.`

	match := Detect(content)
	if match == nil {
		t.Fatal("expected MPL-2.0 match, got nil")
	}
	if match.SPDXID != "MPL-2.0" {
		t.Errorf("expected MPL-2.0, got %s (confidence: %.2f)", match.SPDXID, match.Confidence)
	}
}

func TestDetect_Unlicense(t *testing.T) {
	content := `This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

For more information, please refer to <http://unlicense.org>`

	match := Detect(content)
	if match == nil {
		t.Fatal("expected Unlicense match, got nil")
	}
	if match.SPDXID != "Unlicense" {
		t.Errorf("expected Unlicense, got %s (confidence: %.2f)", match.SPDXID, match.Confidence)
	}
}

func TestDetect_EmptyContent(t *testing.T) {
	match := Detect("")
	if match != nil {
		t.Errorf("expected nil for empty content, got %s", match.SPDXID)
	}
}

func TestDetect_ShortContent(t *testing.T) {
	match := Detect("This is a short text that is not a license.")
	if match != nil {
		t.Errorf("expected nil for short non-license content, got %s", match.SPDXID)
	}
}

func TestDetect_NonLicenseText(t *testing.T) {
	content := `This is a README file for a software project.
It contains installation instructions and usage examples.
There is no license information here, just documentation.`
	match := Detect(content)
	if match != nil {
		t.Errorf("expected nil for non-license content, got %s", match.SPDXID)
	}
}

func TestNormalize_RemovesCopyrightLines(t *testing.T) {
	text := `Copyright (c) 2024 John Doe
All rights reserved.
Permission is hereby granted, free of charge.`
	normalized := normalize(text)
	if contains(normalized, "copyright") {
		t.Errorf("normalize should remove copyright lines, got: %s", normalized)
	}
	if contains(normalized, "all rights reserved") {
		t.Errorf("normalize should remove 'all rights reserved' lines, got: %s", normalized)
	}
}

func TestNormalize_LowercasesAndStripsPunctuation(t *testing.T) {
	text := `THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND!`
	normalized := normalize(text)
	if contains(normalized, "THE") {
		t.Errorf("normalize should lowercase, got: %s", normalized)
	}
	if contains(normalized, "\"") {
		t.Errorf("normalize should strip quotes, got: %s", normalized)
	}
}

func TestDiceCoefficient_IdenticalSets(t *testing.T) {
	a := extractBigrams("hello world")
	dice := diceCoefficient(a, a)
	if dice != 1.0 {
		t.Errorf("identical sets should have dice=1.0, got %.2f", dice)
	}
}

func TestDiceCoefficient_DisjointSets(t *testing.T) {
	a := extractBigrams("abcdef")
	b := extractBigrams("ghijkl")
	dice := diceCoefficient(a, b)
	if dice != 0.0 {
		t.Errorf("disjoint sets should have dice=0.0, got %.2f", dice)
	}
}

func TestExtractBigrams(t *testing.T) {
	bigrams := extractBigrams("hello")
	if len(bigrams) != 4 {
		t.Errorf("expected 4 bigrams from 'hello', got %d", len(bigrams))
	}
	if !bigrams["he"] {
		t.Errorf("expected 'he' bigram")
	}
	if !bigrams["el"] {
		t.Errorf("expected 'el' bigram")
	}
	if !bigrams["ll"] {
		t.Errorf("expected 'll' bigram")
	}
	if !bigrams["lo"] {
		t.Errorf("expected 'lo' bigram")
	}
}

// contains is a helper for string containment check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
