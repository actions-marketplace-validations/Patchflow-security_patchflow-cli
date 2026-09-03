package licensedetect

// signatures is the database of known license signatures used for text-based
// detection. Each entry contains:
//   - SPDXID: the SPDX identifier
//   - Name: human-readable name
//   - keyPhrases: distinctive substrings from the license text
//   - templateBigrams: pre-computed bigrams from the normalized license text
//
// The key phrases are chosen to be unique to each license — they should not
// appear in other licenses. The template text is the canonical license text
// with copyright lines removed and normalized.
//
// Note: We use a subset of each license's most distinctive text rather than
// the full text to keep the binary size reasonable. The n-gram matching still
// works well with ~500-1000 characters of distinctive text.
var signatures = buildSignatures()

func buildSignatures() []LicenseSignature {
	sigs := []LicenseSignature{
		// MIT License
		{
			SPDXID: "MIT",
			Name:   "MIT License",
			keyPhrases: []string{
				"permission is hereby granted free of charge to any person obtaining a copy",
				"the software is provided as is without warranty of any kind",
				"permission is hereby granted free of charge",
			},
			templateBigrams: extractBigrams(normalize(mitText)),
		},
		// Apache 2.0
		{
			SPDXID: "Apache-2.0",
			Name:   "Apache License, Version 2.0",
			keyPhrases: []string{
				"apache license version 2 0",
				"licensed under the apache license version 2 0",
				"unless required by applicable law or agreed to in writing software",
			},
			templateBigrams: extractBigrams(normalize(apache2Text)),
		},
		// BSD 2-Clause
		{
			SPDXID: "BSD-2-Clause",
			Name:   "BSD 2-Clause License",
			keyPhrases: []string{
				"redistribution and use in source and binary forms with or without modification",
				"are permitted provided that the following conditions are met",
				"this software is provided by the copyright holders and contributors as is",
			},
			templateBigrams: extractBigrams(normalize(bsd2Text)),
		},
		// BSD 3-Clause
		{
			SPDXID: "BSD-3-Clause",
			Name:   "BSD 3-Clause License",
			keyPhrases: []string{
				"neither the name of",
				"may be used to endorse or promote products derived from this software",
				"redistribution and use in source and binary forms with or without modification",
			},
			templateBigrams: extractBigrams(normalize(bsd3Text)),
		},
		// ISC License
		{
			SPDXID: "ISC",
			Name:   "ISC License",
			keyPhrases: []string{
				"permission to use copy modify and or distribute this software for any purpose",
				"this software is provided as is",
				"with or without fee is hereby granted",
			},
			templateBigrams: extractBigrams(normalize(iscText)),
		},
		// MPL 2.0
		{
			SPDXID: "MPL-2.0",
			Name:   "Mozilla Public License, Version 2.0",
			keyPhrases: []string{
				"mozilla public license version 2 0",
				"this source code form is subject to the terms of the mozilla public license",
			},
			templateBigrams: extractBigrams(normalize(mpl2Text)),
		},
		// GPL 2.0
		{
			SPDXID: "GPL-2.0",
			Name:   "GNU General Public License v2.0",
			keyPhrases: []string{
				"gnu general public license version 2",
				"free software foundation either version 2 of the license",
				"this program is free software you can redistribute it and or modify",
			},
			templateBigrams: extractBigrams(normalize(gpl2Text)),
		},
		// GPL 3.0
		{
			SPDXID: "GPL-3.0",
			Name:   "GNU General Public License v3.0",
			keyPhrases: []string{
				"gnu general public license version 3",
				"free software foundation either version 3 of the license",
				"this program is free software you can redistribute it and or modify",
			},
			templateBigrams: extractBigrams(normalize(gpl3Text)),
		},
		// LGPL 2.1
		{
			SPDXID: "LGPL-2.1",
			Name:   "GNU Lesser General Public License v2.1",
			keyPhrases: []string{
				"gnu lesser general public license",
				"version 2 1 of the license",
				"this library is free software you can redistribute it and or modify",
			},
			templateBigrams: extractBigrams(normalize(lgpl21Text)),
		},
		// LGPL 3.0
		{
			SPDXID: "LGPL-3.0",
			Name:   "GNU Lesser General Public License v3.0",
			keyPhrases: []string{
				"gnu lesser general public license",
				"version 3 of the license",
				"this library is free software you can redistribute it and or modify",
			},
			templateBigrams: extractBigrams(normalize(lgpl3Text)),
		},
		// AGPL 3.0
		{
			SPDXID: "AGPL-3.0",
			Name:   "GNU Affero General Public License v3.0",
			keyPhrases: []string{
				"gnu affero general public license",
				"affero general public license version 3",
			},
			templateBigrams: extractBigrams(normalize(agpl3Text)),
		},
		// Unlicense
		{
			SPDXID: "Unlicense",
			Name:   "The Unlicense",
			keyPhrases: []string{
				"this is free and unencumbered software released into the public domain",
				"unlicense",
			},
			templateBigrams: extractBigrams(normalize(unlicenseText)),
		},
		// Boost Software License 1.0
		{
			SPDXID: "BSL-1.0",
			Name:   "Boost Software License, Version 1.0",
			keyPhrases: []string{
				"boost software license version 1 0",
				"permission is hereby granted to use copy or modify this software",
			},
			templateBigrams: extractBigrams(normalize(bsl1Text)),
		},
		// CC0 1.0
		{
			SPDXID: "CC0-1.0",
			Name:   "Creative Commons Zero v1.0 Universal",
			keyPhrases: []string{
				"creative commons zero",
				"the person who associated a work with this deed has dedicated the work to the public domain",
				"cc0 1 0 universal",
			},
			templateBigrams: extractBigrams(normalize(cc0Text)),
		},
		// Zlib License
		{
			SPDXID: "Zlib",
			Name:   "zlib License",
			keyPhrases: []string{
				"this software is provided as is without any express or implied warranty",
				"zlib",
				"originally written by",
			},
			templateBigrams: extractBigrams(normalize(zlibText)),
		},
		// WTFPL
		{
			SPDXID: "WTFPL",
			Name:   "Do What The F*ck You Want To Public License",
			keyPhrases: []string{
				"do what the fuck you want to public license",
				"do what the f ck you want to public license",
			},
			templateBigrams: extractBigrams(normalize(wtfplText)),
		},
		// Python License (PSF)
		{
			SPDXID: "Python-2.0",
			Name:   "Python Software Foundation License",
			keyPhrases: []string{
				"python software foundation license",
				"psf license agreement",
				"python software foundation",
			},
			templateBigrams: extractBigrams(normalize(pythonText)),
		},
		// Ruby License
		{
			SPDXID: "Ruby",
			Name:   "Ruby License",
			keyPhrases: []string{
				"ruby is copyrighted free software",
				"you can redistribute it and or modify it under the same terms as ruby",
			},
			templateBigrams: extractBigrams(normalize(rubyText)),
		},
		// Eclipse Public License 1.0
		{
			SPDXID: "EPL-1.0",
			Name:   "Eclipse Public License 1.0",
			keyPhrases: []string{
				"eclipse public license version 1 0",
				"eclipse public license 1 0",
			},
			templateBigrams: extractBigrams(normalize(epl1Text)),
		},
		// Eclipse Public License 2.0
		{
			SPDXID: "EPL-2.0",
			Name:   "Eclipse Public License 2.0",
			keyPhrases: []string{
				"eclipse public license version 2 0",
				"eclipse public license 2 0",
			},
			templateBigrams: extractBigrams(normalize(epl2Text)),
		},
		// CDDL 1.0
		{
			SPDXID: "CDDL-1.0",
			Name:   "Common Development and Distribution License 1.0",
			keyPhrases: []string{
				"common development and distribution license",
				"cddl",
			},
			templateBigrams: extractBigrams(normalize(cddl1Text)),
		},
		// Artistic License 2.0
		{
			SPDXID: "Artistic-2.0",
			Name:   "Artistic License 2.0",
			keyPhrases: []string{
				"artistic license 2 0",
				"this package is distributed in the hope that it will be useful",
			},
			templateBigrams: extractBigrams(normalize(artistic2Text)),
		},
		// PostgreSQL License
		{
			SPDXID: "PostgreSQL",
			Name:   "PostgreSQL License",
			keyPhrases: []string{
				"permission to use copy modify and distribute this software and its documentation",
				"postgresql",
			},
			templateBigrams: extractBigrams(normalize(postgresqlText)),
		},
		// OpenSSL / Apache 2.0 with SSL exception
		{
			SPDXID: "OpenSSL",
			Name:   "Apache-2.0 with OpenSSL exception",
			keyPhrases: []string{
				"openssl",
				"apache license version 2 0",
			},
			templateBigrams: extractBigrams(normalize(opensslText)),
		},
		// Go License (BSD-3-Clause variant)
		{
			SPDXID: "BSD-3-Clause",
			Name:   "BSD 3-Clause License (Go variant)",
			keyPhrases: []string{
				"redistribution and use in source and binary forms with or without modification",
				"neither the name of google inc",
			},
			templateBigrams: extractBigrams(normalize(goLicenseText)),
		},
		// Vim License
		{
			SPDXID: "Vim",
			Name:   "Vim License",
			keyPhrases: []string{
				"vim license",
				"charityware",
			},
			templateBigrams: extractBigrams(normalize(vimText)),
		},
		// PHP License
		{
			SPDXID: "PHP-3.01",
			Name:   "PHP License v3.01",
			keyPhrases: []string{
				"the php license version 3 01",
				"this license is freely reusable for any application",
			},
			templateBigrams: extractBigrams(normalize(phpText)),
		},
		// BSL 1.1 (Business Source License)
		{
			SPDXID: "BUSL-1.1",
			Name:   "Business Source License 1.1",
			keyPhrases: []string{
				"business source license",
				"change date",
				"change license",
			},
			templateBigrams: extractBigrams(normalize(busl11Text)),
		},
		// SSPL 1.0 (Server Side Public License)
		{
			SPDXID: "SSPL-1.0",
			Name:   "Server Side Public License v1",
			keyPhrases: []string{
				"server side public license",
				"sspl",
			},
			templateBigrams: extractBigrams(normalize(sspl1Text)),
		},
		// EUPL 1.2
		{
			SPDXID: "EUPL-1.2",
			Name:   "European Union Public Licence 1.2",
			keyPhrases: []string{
				"european union public licence",
				"eupl",
				"licensed under the european union public licence",
			},
			templateBigrams: extractBigrams(normalize(eupl12Text)),
		},
		// AFL 3.0
		{
			SPDXID: "AFL-3.0",
			Name:   "Academic Free License v3.0",
			keyPhrases: []string{
				"academic free license",
				"afl",
			},
			templateBigrams: extractBigrams(normalize(afl3Text)),
		},
		// CC BY 4.0
		{
			SPDXID: "CC-BY-4.0",
			Name:   "Creative Commons Attribution 4.0",
			keyPhrases: []string{
				"creative commons attribution 4 0 international",
				"creative commons corporation",
			},
			templateBigrams: extractBigrams(normalize(ccby4Text)),
		},
		// CC BY-SA 4.0
		{
			SPDXID: "CC-BY-SA-4.0",
			Name:   "Creative Commons Attribution-ShareAlike 4.0",
			keyPhrases: []string{
				"creative commons attribution sharealike 4 0 international",
			},
			templateBigrams: extractBigrams(normalize(ccbysa4Text)),
		},
		// Beerware
		{
			SPDXID: "Beerware",
			Name:   "Beerware License",
			keyPhrases: []string{
				"beerware",
				"buy me a beer",
				"as long as you retain this notice you can do whatever you want with this stuff",
			},
			templateBigrams: extractBigrams(normalize(beerwareText)),
		},
		// 0BSD
		{
			SPDXID: "0BSD",
			Name:   "BSD Zero Clause License",
			keyPhrases: []string{
				"permission to use copy modify and or distribute this software for any purpose",
				"with or without fee is hereby granted",
			},
			templateBigrams: extractBigrams(normalize(zerobsdText)),
		},
		// BlueOak-1.0.0
		{
			SPDXID: "BlueOak-1.0.0",
			Name:   "Blue Oak Model License 1.0.0",
			keyPhrases: []string{
				"blue oak model license",
				"this is a human readable summary",
			},
			templateBigrams: extractBigrams(normalize(blueoakText)),
		},
	}

	return sigs
}
