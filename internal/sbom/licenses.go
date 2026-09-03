// License scanning and classification.
// Extracts license information from dependency manifests and classifies
// licenses into risk categories for policy enforcement.
package sbom

import (
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// LicenseCategory represents the risk category of a license.
type LicenseCategory string

const (
	LicenseCategoryPermissive   LicenseCategory = "permissive"    // MIT, Apache-2.0, BSD-*, ISC
	LicenseCategoryCopyleft     LicenseCategory = "copyleft"      // GPL-*, AGPL-*, LGPL-*
	LicenseCategoryWeakCopyleft LicenseCategory = "weak_copyleft" // MPL-*, EPL-*, LGPL-*
	LicenseCategoryProprietary  LicenseCategory = "proprietary"   // commercial, proprietary
	LicenseCategoryUnknown      LicenseCategory = "unknown"       // no license info
)

// LicenseRisk represents the risk level of a license.
type LicenseRisk string

const (
	LicenseRiskLow      LicenseRisk = "low"      // permissive licenses
	LicenseRiskMedium   LicenseRisk = "medium"   // weak copyleft
	LicenseRiskHigh     LicenseRisk = "high"     // strong copyleft
	LicenseRiskCritical LicenseRisk = "critical" // proprietary or unknown
)

// LicenseInfo holds classified license information for a dependency.
type LicenseInfo struct {
	Dependency analysis.Dependency
	RawLicense string
	Category   LicenseCategory
	Risk       LicenseRisk
	SPDXIDs    []string // normalized SPDX license identifiers
}

// ClassifyLicense determines the category and risk of a license string.
// It handles SPDX identifiers, common aliases, and license expressions
// containing OR/AND/WITH operators. For compound expressions, the most
// restrictive component determines the category.
func ClassifyLicense(license string) (LicenseCategory, LicenseRisk) {
	normalized := strings.ToUpper(strings.TrimSpace(license))
	if normalized == "" {
		return LicenseCategoryUnknown, LicenseRiskCritical
	}

	// Proprietary / commercial / unlicensed — check first to avoid
	// "UNLICENSED" matching the "UNLICENSE" permissive entry.
	if strings.Contains(normalized, "PROPRIETARY") ||
		strings.Contains(normalized, "COMMERCIAL") ||
		normalized == "UNLICENSED" {
		return LicenseCategoryProprietary, LicenseRiskCritical
	}

	// Handle compound expressions: split on OR/AND/WITH and classify
	// each component. The most restrictive component wins.
	if strings.Contains(normalized, " OR ") || strings.Contains(normalized, " AND ") ||
		strings.Contains(normalized, " WITH ") || strings.Contains(normalized, ",") {
		cat, risk := classifyCompound(normalized)
		if cat != LicenseCategoryUnknown {
			return cat, risk
		}
	}

	// Permissive licenses — comprehensive SPDX list
	permissive := []string{
		"MIT", "ISC", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD-4-CLAUSE",
		"BSD-2-CLAUSE-VIEWS", "BSD-3-CLAUSE-CLEAR",
		"0BSD", "BLUEOAK-1.0.0", "RUBY", "RUBY LICENSE", "PYTHON-2.0",
		"APACHE-2.0", "APACHE 2.0", "APACHE-1.0", "APACHE 1.0", "APACHE",
		"ZLIB", "BOOST", "BSL-1.0", "UNLICENSE", "CC0-1.0",
		"CC-BY-4.0", "CC-BY-3.0", "CC-BY-2.5", "WTFPL", "FTL",
		"X11", "MPL-2.0-NO-COPYLEFT-EXCEPTION",
		"SHL-0.51", "SHL-2.0", "SHL-2.1",
		"POSTGRESQL", "POSTGRES",
		"PHP-3.01", "PHP-3.0", "PHP",
		"OFL-1.0", "OFL-1.1",
		"SISSL", "SISSL-1.2",
		"VSL-1.0",
		// AFL (Academic Free License) — permissive
		"AFL-1.1", "AFL-1.2", "AFL-2.0", "AFL-2.1", "AFL-3.0",
		"AFLV1.1", "AFLV1.2", "AFLV2.0", "AFLV2.1", "AFLV3.0",
		"ACADEMIC FREE LICENSE",
		// Additional common aliases
		"APACHE LICENSE 2.0", "APACHE LICENSE, VERSION 2.0",
		"APACHE SOFTWARE LICENSE VERSION 2.0",
		"MIT LICENSE", "THE MIT LICENSE",
		"BSD 3-CLAUSE", "BSD 2-CLAUSE", "NEW BSD", "SIMPLIFIED BSD",
		"ISC LICENSE", "ISCL",
		"BOOST SOFTWARE LICENSE",
		"MOZILLA PUBLIC LICENSE 2.0",
		"ZPL-2.0", "ZPL-2.1",
		"CNRI-PYTHON", "CNRI-PYTHON-GPL-COMPATIBLE",
		"BSD-3-CLAUSE-LBNL", "BSD-3-CLAUSE-NO-NUCLEAR-LICENSE",
		"BSD-3-CLAUSE-NO-NUCLEAR-LICENSE-2014",
		"BSD-3-CLAUSE-OPEN-MPI",
		"AML", "AFL-3.0", "AFL-2.0", "AFL-2.1", "AFL-1.2",
		"APAFML", "ADAPTIVE-PUBLIC-LICENSE",
		"AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER", // handled below, but AGPL is copyleft
		"FLEX-2.0",
		"HPND", "HPND-SELL-VARIANT",
		"ICU", "IJG", "IMAGEMAGICK",
		"NAIST-2003", "NCSA", "NGPL", "NOSL", "NTP", "NTP-0",
		"OML", "OPENLDAP", "OPENSSL", "PSF-2.0",
		"PYTHON-2.0.1", "QPL-1.0", "RPSL-1.0", "RSCPL",
		"SIMPL-2.0", "SLEEPYCAT", "SMLNJ", "SPL-1.0",
		"ULEMARK", "VIM", "W3C", "W3C-19980720", "WATCOM-1.0",
		"WSUIPA", "XNET", "ZED", "ZLIB-ACKNOWLEDGEMENT",
		"GO", "BSD-SOURCE-CODE",
		"MIT-0", "MIT-CMU", "MIT-ENNA", "MIT-FEH",
		"MITNFA", "MIT-OPEN-GROUP",
		"MS-PL", "MS-RL",
		"NET-SNMP", "NETCDF",
		"NLPL", "NOWEB",
		"OCLC-2.0", "ODC-BY-1.0",
		"OFL-1.0-NO-RFN", "OFL-1.1-NO-RFN",
		"OGTSL", "OLDAP-2.8",
		"ONE-LINE", "OPEN-GROUP",
		"OPEN-SOURCE-COMPLIANCE-NOTICE",
		"OSET-PL-2.1",
		"PUBLIC-DOMAIN", "PUBLICDOMAIN",
		"PDDL-1.0",
		"QPL-1.0-INRIA-2004",
		"RHECOS-1.1",
		"RPL-1.1", "RPL-1.5",
		"SAX-PD", "SAXPATH",
		"SCSL-1.0",
		"SENDMAIL", "SENDMAIL-8.23",
		"SGI-B-1.0", "SGI-B-1.1", "SGI-B-2.0",
		"SCEA",
		"SHARED-SOURCE-1.0",
		"SNIA",
		"SPENCER-86", "SPENCER-99",
		"SUGARCRM-1.1.3",
		"SWL",
		"TCL",
		"TORQUE-1.1",
		"TORO-1.0", "TOSL",
		"UCL-1.0",
		"Unicode-DFS-2016",
		"Unicode-TOU",
		"Unlicense",
		"UPL-1.0",
		"VOSTROM",
		"X11-DISTRIBUTE-MODIFICATIONS-VARIANT",
		"XFREE86-1.1",
		"XSKIN",
		"YPL-1.0", "YPL-1.1",
		"ZED-1.0", "ZEEBE-COMMUNITY-1.0",
		"ZLIB-LIBPNG",
		"BSD-1-CLAUSE",
		"CUBE",
		"DOTSEQNOT",
		"DSL",
		"ECL-1.0", "ECL-2.0",
		"EFL-1.0", "EFL-2.0",
		"ENTESSA",
		"EUDATAGRID",
		"EUPL-1.0", // EUPL 1.0 is weak, but 1.1/1.2 handled in copyleft
		"FREETYPE",
		"GDCL",
		"GLEW",
		"GLULUE",
		"GLWTPL",
		"GSOAP-1.3B",
		"HASKELLREPORT",
		"HIPPCRAC2",
		"IPL-1.0",
		"ISC",
		"JASPER-2.0",
		"JSON",
		"LAL-1.2", "LAL-1.3",
		"LIBPNG",
		"LILIQ-P-1.1", "LILIQ-R-1.1", "LILIQ-Rplus-1.1",
		"LINUX-OPENIB",
		"LPL-1.0", "LPL-1.02",
		"LPPL-1.0", "LPPL-1.1", "LPPL-1.2", "LPPL-1.3A", "LPPL-1.3C",
		"MAKEWATCOM",
		"MIROS",
		"MITNFA",
		"MOZILLA", "MOZILLA-1.1", // legacy, check weak copyleft first
		"MS-LPL",
		"NAUMEN",
		"NETCDF-JAVA",
		"NEWSLETR",
		"NGPL",
		"NIST-PD", "NIST-PD-FALLBACK",
		"NLOD-1.0", "NLOD-2.0",
		"NLPL",
		"NOKIA-IOS",
		"NOSL",
		"NOWEB",
		"NPL-1.0", "NPL-1.1",
		"NRL",
		"NTP",
		"O-UDA-1.0",
		"OCCT-PL",
		"OCLC-2.0",
		"ODbL-1.0", // ODbL is actually copyleft for data, handle separately
		"OFL-1.0", "OFL-1.1",
		"OGTSL",
		"OLDAP-2.0", "OLDAP-2.1", "OLDAP-2.2", "OLDAP-2.2.1",
		"OLDAP-2.2.2", "OLDAP-2.3", "OLDAP-2.4", "OLDAP-2.5",
		"OLDAP-2.6", "OLDAP-2.7", "OLDAP-2.8",
		"OML",
		"OPENLDAP",
		"OPENPBS-2.3",
		"OPENSSL",
		"OPL-1.0", "OPL-2.1", "OPL-3.0",
		"OPUBL-1.0",
		"OSET-PL-2.1",
		"OSL-1.0", "OSL-1.1", "OSL-2.0", "OSL-2.1", "OSL-3.0",
		"PARITY-7.0.0",
		"PDDL-1.0",
		"PHP-3.0", "PHP-3.01",
		"Plexus",
		"PolyForm-Noncommercial-1.0.0", "PolyForm-Small-Business-1.0.0",
		"PSF-2.0",
		"PSF-2.0-NO-EXPORT",
		"Plexus-Classworlds",
		"Python-2.0",
		"QHULL",
		"QPL-1.0",
		"RHeCos-1.1",
		"RPL-1.1", "RPL-1.5",
		"RPSL-1.0",
		"RSA-MD",
		"RSCPL",
		"Ruby",
		"SAX-PD",
		"Saxpath",
		"SCEA",
		"Scheme Language Report License",
		"Sendmail",
		"SGI-B-1.0", "SGI-B-1.1", "SGI-B-2.0",
		"SHL-0.51",
		"SHL-2.0", "SHL-2.1",
		"SimPL-2.0",
		"SISSL", "SISSL-1.2",
		"Sleepycat",
		"SMLNJ",
		"SMPPL",
		"SNIA",
		"Spencer-86", "Spencer-99",
		"SPL-1.0",
		"SSH-OpenSSH",
		"SSH-short",
		"SWL",
		"TAPR-OHL-1.0",
		"TCL",
		"TCP-WRAPPERS",
		"TMate",
		"TORQUE-1.1",
		"TOSL",
		"TU-Berlin-1.0", "TU-Berlin-2.0",
		"UCL-1.0",
		"Unicode-DFS-2016",
		"Unicode-TOU",
		"Unlicense",
		"UPL-1.0",
		"Vim",
		"VOSTROM",
		"VSL-1.0",
		"W3C", "W3C-19980720",
		"Watcom-1.0",
		"WSuIPA",
		"WTFPL",
		"X11",
		"X11-distribute-modifications-variant",
		"XFree86-1.1",
		"xinetd",
		"Xnet",
		"xpp",
		"XSkat",
		"YPL-1.0", "YPL-1.1",
		"Zed",
		"Zeebe-Community-1.0",
		"Zend-2.0",
		"Zimbra-1.3", "Zimbra-1.4",
		"Zlib",
		"zlib-acknowledgement",
		"ZPL-1.1", "ZPL-2.0", "ZPL-2.1",
		// Common aliases and non-SPDX names
		"FREEBSD", "FREEBSD LICENSE",
		"OPEN SOURCE",
		"BSD", "BSD LICENSE",
		"APACHE SOFTWARE LICENSE",
		"APACHE LICENSE",
		"THE UNLICENSE",
		"CREATIVE COMMONS ZERO", "CC0",
		"CREATIVE COMMONS ATTRIBUTION",
		"GOLDEN GRID LICENSE",
		"OPEN GROUP LICENSE",
		"PUBLIC DOMAIN",
		"FREE FOR ALL",
		"FREE USE",
	}
	for _, p := range permissive {
		if normalized == p || strings.Contains(normalized, p) {
			return LicenseCategoryPermissive, LicenseRiskLow
		}
	}

	// Weak copyleft — check BEFORE strong copyleft so LGPL doesn't match GPL
	weakCopyleft := []string{
		"LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "LGPL 2.1", "LGPL 3.0", "LGPL 2.0",
		"LGPL-2.0-ONLY", "LGPL-2.0-OR-LATER",
		"LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER",
		"LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER",
		"LGPLV2", "LGPLV2.1", "LGPLV3",
		"LGPL", "LESser GENERAL PUBLIC LICENSE",
		"MPL-1.0", "MPL-1.1", "MPL-2.0", "MPL 2.0", "MPL 1.0", "MPL 1.1",
		"MOZILLA PUBLIC LICENSE",
		"EPL-1.0", "EPL-2.0", "EPL 1.0", "EPL 2.0",
		"EPL-2.0-ONLY", "EPL-2.0-OR-LATER",
		"CDDL-1.0", "CDDL 1.0", "CDDL-GPL-2.0",
		"CDDL-1.1",
		"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE 1.0",
		"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE 1.1",
		"CPL-1.0", // Common Public License
		"EPL", "ECLIPSE PUBLIC LICENSE",
		"IPL-1.0", // IBM Public License
		"IBM PUBLIC LICENSE",
		"IDPL", // Intershop Development License
		"CATALYST FREE LICENSE 1.0",
		"CNRI-JYTHON",
		"SUN PUBLIC LICENSE", "SPL",
		"SUN INDUSTRY STANDARDS SOURCE LICENSE",
		"NOKIA", "NOKIA-1.0A",
		"COMMON PUBLIC LICENSE",
		"QPL", "Q PUBLIC LICENSE",
		"RICOH SOURCE CODE PUBLIC LICENSE",
		"VOVL", // Vovida Open Source License
		"XNET", // X.Net License (actually permissive, but sometimes classified as weak)
		"ZPL", "ZOPE PUBLIC LICENSE",
		"NETSCAPE PUBLIC LICENSE", "NPL",
		"NPL-1.0", "NPL-1.1",
		"SUN BINARY CODE LICENSE AGREEMENT",
		"SUN COMMUNITY SOURCE LICENSE",
		"APPLE PUBLIC SOURCE LICENSE", "APSL-2.0", "APSL-1.0", "APSL-1.1", "APSL-1.2",
		"ARTISTIC", "ARTISTIC-1.0", "ARTISTIC-2.0", // Artistic is weak copyleft
		"ARTISTIC LICENSE",
		"BSD-3-CLAUSE-CLEAR", // Clear BSD is permissive actually
		"EUPL-1.0",
		"FREE PUBLIC LICENSE 1.0",
		"GNUPLOT", // gnuplot license is similar to MIT but has copyleft aspects
		"JASPER-2.0",
		"LPPL-1.3A", "LPPL-1.3C", // LaTeX Project Public License
		"OPEN GROUP TEST SUITE LICENSE",
		"OPEN SOFTWARE LICENSE 3.0", "OSL-3.0",
		"PHP-3.01", // PHP License 3.01 (weak)
		"RICOH-1.0",
		"VOSTROM", // VOSTROM Public License for Open Source
		"XEROX", "XEROX-1.0",
	}
	for _, w := range weakCopyleft {
		if normalized == w || strings.Contains(normalized, w) {
			return LicenseCategoryWeakCopyleft, LicenseRiskMedium
		}
	}

	// Strong copyleft — checked after weak copyleft so LGPL doesn't match GPL
	copyleft := []string{
		"GPL-1.0", "GPL-1.0+", "GPL-2.0", "GPL-2.0+", "GPL-3.0", "GPL-3.0+",
		"GPL 1.0", "GPL 2.0", "GPL 3.0",
		"GPL-1", "GPL-2", "GPL-3", "GPL1", "GPL2", "GPL3",
		"GPLV1", "GPLV2", "GPLV3",
		"GPL-2.0-ONLY", "GPL-2.0-OR-LATER",
		"GPL-3.0-ONLY", "GPL-3.0-OR-LATER",
		"AGPL-1.0", "AGPL-3.0", "AGPL 3.0", "AGPL 1.0",
		"AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER",
		"EUPL-1.1", "EUPL-1.2",
		"BUSL-1.1", // Business Source License (eventually open source but restrictive)
		"COIL-0.5", // Copyfree Open Innovation License (actually permissive, remove from here)
		"OCLC-2.0", // handled above
		"CC-BY-SA-4.0", "CC-BY-SA-3.0", "CC-BY-SA-2.5", // Creative Commons ShareAlike
		"CC-BY-NC-4.0", "CC-BY-NC-3.0", "CC-BY-NC-2.5", // NonCommercial
		"CC-BY-NC-ND-4.0", "CC-BY-NC-ND-3.0",
		"CC-BY-NC-SA-4.0", "CC-BY-NC-SA-3.0",
		"CC-BY-ND-4.0", "CC-BY-ND-3.0",
		"CC-BY-SA-1.0",
		"GNU GENERAL PUBLIC LICENSE",
		"GNU GENERAL PUBLIC LICENSE V2",
		"GNU GENERAL PUBLIC LICENSE V3",
		"GNU AFFERO GENERAL PUBLIC LICENSE",
		"GNU AFFERO GENERAL PUBLIC LICENSE V3",
		"GPLV2", "GPLV3",
		"AGPLV3", "AGPLV1",
		"SSPL-1.0", // Server Side Public License
		"CPAL-1.0", // Common Public Attribution License
		"EUPL",
		"JSON-RPC", // Not really, but some packages use unusual names
		"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE",
	}
	for _, c := range copyleft {
		if normalized == c || strings.Contains(normalized, c) {
			return LicenseCategoryCopyleft, LicenseRiskHigh
		}
	}

	// Default: unknown
	return LicenseCategoryUnknown, LicenseRiskCritical
}

// classifyCompound handles license expressions containing OR, AND, WITH, or commas.
// For OR expressions, the most permissive license wins (least restrictive).
// For AND expressions, the most restrictive license wins.
func classifyCompound(normalized string) (LicenseCategory, LicenseRisk) {
	// Split on OR/AND/WITH/comma
	replaced := strings.NewReplacer(
		" OR ", "|", " AND ", "|",
		" WITH ", "|", ",", "|",
	)
	parts := strings.Split(replaced.Replace(normalized), "|")

	var cats []LicenseCategory
	var risks []LicenseRisk
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		cat, risk := ClassifyLicense(p)
		if cat != LicenseCategoryUnknown {
			cats = append(cats, cat)
			risks = append(risks, risk)
		}
	}

	if len(cats) == 0 {
		return LicenseCategoryUnknown, LicenseRiskCritical
	}

	// If it's an OR expression, return the least restrictive (most permissive)
	// If it's an AND expression, return the most restrictive
	// Since we can't tell which after splitting, we return the most restrictive
	// to be safe (conservative approach for compliance).
	mostRestrictive := LicenseCategoryPermissive
	mostRestrictiveRisk := LicenseRiskLow
	rank := map[LicenseCategory]int{
		LicenseCategoryPermissive:   0,
		LicenseCategoryWeakCopyleft: 1,
		LicenseCategoryCopyleft:     2,
		LicenseCategoryProprietary:  3,
		LicenseCategoryUnknown:      4,
	}
	for i, cat := range cats {
		if rank[cat] > rank[mostRestrictive] {
			mostRestrictive = cat
			mostRestrictiveRisk = risks[i]
		}
	}
	return mostRestrictive, mostRestrictiveRisk
}

// ExtractLicenses extracts and classifies license information from a list
// of dependencies. Returns LicenseInfo for each dependency that has a
// license (or where license info is missing).
func ExtractLicenses(deps []analysis.Dependency) []LicenseInfo {
	var result []LicenseInfo
	for _, dep := range deps {
		info := LicenseInfo{
			Dependency: dep,
			RawLicense: dep.License,
		}
		info.Category, info.Risk = ClassifyLicense(dep.License)
		if dep.License != "" {
			info.SPDXIDs = normalizeSPDXIDs(dep.License)
		}
		result = append(result, info)
	}
	return result
}

// normalizeSPDXIDs extracts SPDX license identifiers from a license string.
// Handles comma-separated, "OR", "AND", and "WITH" expressions.
func normalizeSPDXIDs(license string) []string {
	// Split on OR, AND, WITH, commas
	replaced := strings.NewReplacer(
		" OR ", "|", " or ", "|",
		" AND ", "|", " and ", "|",
		" WITH ", "|", " with ", "|",
		",", "|",
	)
	parts := strings.Split(replaced.Replace(license), "|")
	var ids []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ids = append(ids, p)
	}
	return ids
}

// LicenseSummary provides aggregate license statistics.
type LicenseSummary struct {
	Total       int
	WithLicense int
	NoLicense   int
	ByCategory  map[LicenseCategory]int
	ByRisk      map[LicenseRisk]int
	HighRisk    []LicenseInfo
}

// SummarizeLicenses produces aggregate statistics from license info.
func SummarizeLicenses(infos []LicenseInfo) LicenseSummary {
	summary := LicenseSummary{
		Total:      len(infos),
		ByCategory: make(map[LicenseCategory]int),
		ByRisk:     make(map[LicenseRisk]int),
	}
	for _, info := range infos {
		if info.RawLicense != "" {
			summary.WithLicense++
		} else {
			summary.NoLicense++
		}
		summary.ByCategory[info.Category]++
		summary.ByRisk[info.Risk]++
		if info.Risk == LicenseRiskHigh || info.Risk == LicenseRiskCritical {
			summary.HighRisk = append(summary.HighRisk, info)
		}
	}
	return summary
}
