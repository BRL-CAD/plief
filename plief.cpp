/*                     P L I E F . C P P
 * BRL-CAD
 *
 * Copyright (c) 2023 United States Government as represented by
 * the U.S. Army Research Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/** @file plief.cpp
 *
 * Use https://github.com/lief-project/LIEF to modify RPATHs in
 * binaries
 */

#include <fstream>
#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include "cxxopts.hpp"
#include "LIEF/ELF.hpp"
#include "LIEF/logging.hpp"

class process_opts {
    public:
    bool clear_mode = false;
    bool classify_mode = false;
    bool print_rpath = false;
    bool print_soname = false;
    bool remove_soname = false;
    bool force_rpath = false; // To manipulate DT_RPATH rather than DT_RUNPATH
    bool report_rpath_changes = false;
    bool set_rpath_if_needed = false;
    bool set_rpath_if_needed_append = false;
    bool set_rpath_if_needed_prepend = false;
    size_t verbose = 0;
    std::string add_rpath_val;
    std::string set_rpath_val;
    std::string set_soname_val;
    std::vector<std::string> stale_rpath_prefixes;
    bool list_output = false;
};

static std::vector<std::string>
rpath_paths(LIEF::ELF::Binary &binfo, bool force_rpath)
{
    LIEF::ELF::DynamicEntry *rp = force_rpath ? binfo.get(LIEF::ELF::DynamicEntry::TAG::RPATH) : binfo.get(LIEF::ELF::DynamicEntry::TAG::RUNPATH);
    if (!rp)
	return {};

    if (force_rpath)
	return reinterpret_cast<LIEF::ELF::DynamicEntryRpath *>(rp)->paths();

    return reinterpret_cast<LIEF::ELF::DynamicEntryRunPath *>(rp)->paths();
}

static std::string
path_list_string(const std::vector<std::string> &paths)
{
    std::ostringstream out;
    for (size_t i = 0; i < paths.size(); i++) {
	if (i)
	    out << ";";
	out << paths[i];
    }
    return out.str();
}

static std::vector<std::string>
split_rpath_string(const std::string &rpath)
{
    std::vector<std::string> paths;
    std::string current;
    for (char c : rpath) {
	if (c == ':' || c == ';') {
	    if (!current.empty())
		paths.push_back(current);
	    current.clear();
	    continue;
	}
	current.push_back(c);
    }
    if (!current.empty())
	paths.push_back(current);
    return paths;
}

static bool
contains_path(const std::vector<std::string> &paths, const std::string &path)
{
    for (const auto &candidate : paths) {
	if (candidate == path)
	    return true;
    }
    return false;
}

static std::vector<std::string>
expand_path_forms(const std::string &input)
{
    namespace fs = std::filesystem;
    std::vector<std::string> forms;
    if (input.empty())
	return forms;

    auto add_form = [&](const fs::path &p) {
	std::string s = p.string();
	if (!s.empty())
	    forms.push_back(s);
    };

    auto add_partial_canonical = [&](const fs::path &p) {
	std::error_code ec;
	fs::path probe = fs::absolute(p, ec);
	if (ec)
	    probe = p;

	fs::path suffix;
	while (!probe.empty() && !fs::exists(probe, ec)) {
	    fs::path parent = probe.parent_path();
	    if (parent == probe)
		break;
	    if (suffix.empty())
		suffix = probe.filename();
	    else
		suffix = probe.filename() / suffix;
	    probe = parent;
	    ec.clear();
	}

	if (probe.empty() || !fs::exists(probe, ec))
	    return;

	ec.clear();
	fs::path canon = fs::canonical(probe, ec);
	if (ec || canon.empty())
	    return;

	if (!suffix.empty())
	    canon /= suffix;
	add_form(canon);
    };

    try {
	fs::path p(input);
	add_form(p);
	std::error_code ec;
	fs::path abs = fs::absolute(p, ec);
	if (!ec)
	    add_form(abs);
	add_form(p.lexically_normal());
	if (!ec)
	    add_form(abs.lexically_normal());

	ec.clear();
	if (fs::exists(p, ec)) {
	    fs::path canon = fs::canonical(p, ec);
	    if (!ec)
		add_form(canon);
	}

	add_partial_canonical(p);
    } catch (...) {
	// Ignore errors (broken symlink, permission denied, etc).
    }

    std::sort(forms.begin(), forms.end(),
	      [](const std::string &a, const std::string &b) {
		  if (a.size() != b.size())
		      return a.size() > b.size();
		  return a > b;
	      });
    forms.erase(std::unique(forms.begin(), forms.end()), forms.end());

    return forms;
}

static std::vector<std::string>
expand_path_forms(const std::vector<std::string> &inputs)
{
    std::vector<std::string> forms;
    for (const auto &input : inputs) {
	std::vector<std::string> input_forms = expand_path_forms(input);
	forms.insert(forms.end(), input_forms.begin(), input_forms.end());
    }

    std::sort(forms.begin(), forms.end(),
	      [](const std::string &a, const std::string &b) {
		  if (a.size() != b.size())
		      return a.size() > b.size();
		  return a > b;
	      });
    forms.erase(std::unique(forms.begin(), forms.end()), forms.end());

    return forms;
}

static std::string
rpath_string(LIEF::ELF::Binary &binfo, bool force_rpath)
{
    return path_list_string(rpath_paths(binfo, force_rpath));
}

static bool
supports_rpath(const LIEF::ELF::Binary &binfo)
{
    LIEF::ELF::Header::FILE_TYPE ftype = binfo.header().file_type();
    return ftype == LIEF::ELF::Header::FILE_TYPE::EXEC || ftype == LIEF::ELF::Header::FILE_TYPE::DYN;
}

static bool
has_path_prefix(const std::string &value, const std::string &prefix)
{
    if (prefix.empty())
	return false;

    if (value == prefix)
	return true;

    if (value.size() <= prefix.size() || value.compare(0, prefix.size(), prefix) != 0)
	return false;

    char last = prefix[prefix.size() - 1];
    if (last == '/' || last == '\\')
	return true;

    char next = value[prefix.size()];
    return next == '/' || next == '\\';
}

static bool
path_is_stale(const std::string &path, const std::vector<std::string> &stale_prefixes)
{
    for (const auto &prefix : stale_prefixes) {
	if (has_path_prefix(path, prefix))
	    return true;
    }
    return false;
}

static bool
rpath_update_needed(const std::vector<std::string> &paths, const std::string &new_rpath, const std::vector<std::string> &stale_prefixes)
{
    if (path_list_string(paths) == new_rpath)
	return false;

    if (paths.empty())
	return true;

    for (const auto &path : paths) {
	if (path_is_stale(path, stale_prefixes))
	    return true;
    }

    return false;
}

static std::vector<std::string>
filtered_rpath_paths(const std::vector<std::string> &existing_paths, const std::string &add_rpath, const std::vector<std::string> &stale_prefixes, bool prepend_add_paths)
{
    std::vector<std::string> filtered;
    std::vector<std::string> add_paths = split_rpath_string(add_rpath);

    if (prepend_add_paths) {
	for (const auto &path : add_paths) {
	    if (!contains_path(filtered, path))
		filtered.push_back(path);
	}
    }

    for (const auto &path : existing_paths) {
	if (!path_is_stale(path, stale_prefixes) && !contains_path(filtered, path))
	    filtered.push_back(path);
    }

    if (prepend_add_paths)
	return filtered;

    for (const auto &path : add_paths) {
	if (!contains_path(filtered, path))
	    filtered.push_back(path);
    }

    return filtered;
}

static void
set_rpath_paths(LIEF::ELF::Binary &binfo, bool force_rpath, const std::vector<std::string> &paths)
{
    if (force_rpath) {
	binfo.remove(LIEF::ELF::DynamicEntry::TAG::RPATH);
	LIEF::ELF::DynamicEntryRpath npe;
	for (const auto &path : paths)
	    npe.append(path);
	binfo.add(npe);
    } else {
	binfo.remove(LIEF::ELF::DynamicEntry::TAG::RUNPATH);
	LIEF::ELF::DynamicEntryRunPath npe;
	for (const auto &path : paths)
	    npe.append(path);
	binfo.add(npe);
    }
}

static bool
file_is_writable(const std::string &path)
{
    std::fstream fs(path, std::ios::in | std::ios::out | std::ios::binary);
    return static_cast<bool>(fs);
}

static std::string
soname_value(LIEF::ELF::Binary *binfo)
{
    LIEF::ELF::DynamicEntry *so = binfo->get(LIEF::ELF::DynamicEntry::TAG::SONAME);
    if (!so)
	return std::string();
    return reinterpret_cast<LIEF::ELF::DynamicSharedObject *>(so)->name();
}

static std::string
json_escape(const std::string &input)
{
    std::ostringstream out;
    for (unsigned char c : input) {
	switch (c) {
	    case '"':
		out << "\\\"";
		break;
	    case '\\':
		out << "\\\\";
		break;
	    case '\b':
		out << "\\b";
		break;
	    case '\f':
		out << "\\f";
		break;
	    case '\n':
		out << "\\n";
		break;
	    case '\r':
		out << "\\r";
		break;
	    case '\t':
		out << "\\t";
		break;
	    default:
		if (c < 0x20) {
		    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c << std::dec;
		} else {
		    out << c;
		}
	}
    }
    return out.str();
}

static int
process_file(const std::string &fname, const process_opts &p)
{
    bool bin_mod = false;
    bool rpath_mod_requested = p.clear_mode || p.add_rpath_val.length() || p.set_rpath_val.length();
    bool rpath_mod_supported = false;

    std::unique_ptr<LIEF::ELF::Binary> binfo = std::unique_ptr<LIEF::ELF::Binary>{LIEF::ELF::Parser::parse(fname)};
    if (!binfo) {
	if (p.classify_mode) {
	    std::cout << "{\"type\":\"OTHER\",\"path\":\"" << json_escape(fname) << "\"}\n";
	    return 0;
	}
	std::cerr << "Not an ELF file: " << fname << "\n";
	return -1;
    }

    if (p.classify_mode) {
	std::cout << "{\"type\":\"ELF\",\"path\":\"" << json_escape(fname) << "\"}\n";
	return 0;
    }

    rpath_mod_supported = supports_rpath(*binfo);

    std::vector<std::string> before_rpath_paths;
    std::string before_rpath;
    if (rpath_mod_supported && rpath_mod_requested && (p.report_rpath_changes || p.set_rpath_val.length()))
	before_rpath_paths = rpath_paths(*binfo, p.force_rpath);
    before_rpath = path_list_string(before_rpath_paths);

    if (rpath_mod_supported && p.clear_mode) {
	if (p.force_rpath) {
	    if (binfo->get(LIEF::ELF::DynamicEntry::TAG::RPATH)) {
		binfo->remove(LIEF::ELF::DynamicEntry::TAG::RPATH);
		bin_mod = true;
	    }
	} else {
	    if (binfo->get(LIEF::ELF::DynamicEntry::TAG::RUNPATH)) {
		binfo->remove(LIEF::ELF::DynamicEntry::TAG::RUNPATH);
		bin_mod = true;
	    }
	}
    }


    if (rpath_mod_supported && p.add_rpath_val.length()) {

	// Adding a path is not destructive to existing RUNPATH values
	if (p.force_rpath) {
	    LIEF::ELF::DynamicEntry *rp = binfo->get(LIEF::ELF::DynamicEntry::TAG::RPATH);
	    LIEF::ELF::DynamicEntryRpath npe;
	    if (rp) {
		LIEF::ELF::DynamicEntryRpath *orig = reinterpret_cast<LIEF::ELF::DynamicEntryRpath*>(rp);
		std::vector<std::string> opaths = orig->paths();
		for (size_t i = 0; i < opaths.size(); i++) {
		    npe.append(opaths[i]);
		}
	    }
	    binfo->remove(LIEF::ELF::DynamicEntry::TAG::RPATH);
	    npe.append(p.add_rpath_val);
	    binfo->add(npe);
	} else {
	    LIEF::ELF::DynamicEntry *rp = binfo->get(LIEF::ELF::DynamicEntry::TAG::RUNPATH);
	    LIEF::ELF::DynamicEntryRunPath npe;
	    if (rp) {
		LIEF::ELF::DynamicEntryRunPath *orig = reinterpret_cast<LIEF::ELF::DynamicEntryRunPath*>(rp);
		std::vector<std::string> opaths = orig->paths();
		for (size_t i = 0; i < opaths.size(); i++) {
		    npe.append(opaths[i]);
		}
	    }
	    binfo->remove(LIEF::ELF::DynamicEntry::TAG::RUNPATH);
	    npe.append(p.add_rpath_val);
	    binfo->add(npe);
	}

	bin_mod = true;
    }

    if (rpath_mod_supported && p.set_rpath_val.length()) {

	// Plain set-rpath is destructive.  In if-needed mode, stale entries
	// are filtered while non-stale entries are preserved.
	bool update_rpath = p.set_rpath_if_needed ? rpath_update_needed(before_rpath_paths, p.set_rpath_val, p.stale_rpath_prefixes) : before_rpath != p.set_rpath_val;
	if (update_rpath) {
	    if (p.set_rpath_if_needed)
		set_rpath_paths(*binfo, p.force_rpath, filtered_rpath_paths(before_rpath_paths, p.set_rpath_val, p.stale_rpath_prefixes, p.set_rpath_if_needed_prepend));
	    else if (p.force_rpath) {
		binfo->remove(LIEF::ELF::DynamicEntry::TAG::RPATH);
		LIEF::ELF::DynamicEntryRpath npe(p.set_rpath_val);
		binfo->add(npe);
	    } else {
		binfo->remove(LIEF::ELF::DynamicEntry::TAG::RUNPATH);
		LIEF::ELF::DynamicEntryRunPath npe(p.set_rpath_val);
		binfo->add(npe);
	    }

	    bin_mod = true;
	}

    }

    if (p.remove_soname) {
	binfo->remove(LIEF::ELF::DynamicEntry::TAG::SONAME);
	bin_mod = true;
    }

    if (p.set_soname_val.length()) {
	// Replace any existing DT_SONAME with the new value
	binfo->remove(LIEF::ELF::DynamicEntry::TAG::SONAME);
	LIEF::ELF::DynamicSharedObject nso(p.set_soname_val);
	binfo->add(nso);
	bin_mod = true;
    }

    bool verify_rpath = bin_mod && rpath_mod_supported && rpath_mod_requested;
    std::vector<std::string> expected_rpath_paths;
    if (verify_rpath)
	expected_rpath_paths = rpath_paths(*binfo, p.force_rpath);

    bool verify_soname = bin_mod && (p.set_soname_val.length() || p.remove_soname);
    std::string expected_soname;
    if (verify_soname)
	expected_soname = soname_value(binfo.get());

    // Write out the new version of the binary, then verify the requested
    // dynamic entries survived serialization and can be parsed back in.
    if (bin_mod) {
	if (!file_is_writable(fname)) {
	    std::cerr << "Unable to open " << fname << " for update\n";
	    return -3;
	}
	std::error_code perms_ec;
	std::filesystem::perms original_perms = std::filesystem::status(fname, perms_ec).permissions();
	bool have_original_perms = !perms_ec;
	binfo->write(fname);
	if (have_original_perms) {
	    std::error_code restore_ec;
	    std::filesystem::permissions(fname, original_perms, std::filesystem::perm_options::replace, restore_ec);
	    if (restore_ec) {
		std::cerr << "Unable to restore permissions on " << fname << ": " << restore_ec.message() << "\n";
		return -4;
	    }
	}

	binfo = std::unique_ptr<LIEF::ELF::Binary>{LIEF::ELF::Parser::parse(fname)};
	if (!binfo) {
	    std::cerr << "Unable to parse " << fname << " after writing\n";
	    return -4;
	}

	if (verify_rpath) {
	    std::string expected_rpath = path_list_string(expected_rpath_paths);
	    std::string updated_rpath = rpath_string(*binfo, p.force_rpath);
	    if (updated_rpath != expected_rpath) {
		std::cerr << "Failed to update " << (p.force_rpath ? "RPATH" : "RUNPATH") << " on " << fname << ": expected \"" << expected_rpath << "\", got \"" << updated_rpath << "\"\n";
		return -4;
	    }
	}

	if (verify_soname) {
	    std::string updated_soname = soname_value(binfo.get());
	    if (updated_soname != expected_soname) {
		std::cerr << "Failed to update SONAME on " << fname << ": expected \"" << expected_soname << "\", got \"" << updated_soname << "\"\n";
		return -4;
	    }
	}
    }

    if (p.report_rpath_changes && rpath_mod_supported && rpath_mod_requested) {
	std::string after_rpath = rpath_string(*binfo, p.force_rpath);
	if (before_rpath != after_rpath)
	    std::cout << fname << "\t" << before_rpath << "\t" << after_rpath << "\n";
    }

    if (p.print_rpath || (!bin_mod && !p.print_soname && !p.report_rpath_changes)) {
	// Doing the lookup here to make sure we have the current, valid binfo
	// entries for printing
	std::vector<std::string> paths = rpath_paths(*binfo, p.force_rpath);
	if (paths.size()) {
	    if (p.list_output)
		std::cout << fname << ":";
	    for (size_t i = 0; i < paths.size() - 1; i++) {
		std::cout << paths[i] << ";";
	    }
	    std::cout << paths[paths.size()-1] << "\n";
	}
    }

    if (p.print_soname) {
	std::string soname = soname_value(binfo.get());
	if (!soname.empty()) {
	    if (p.list_output)
		std::cout << fname << ":";
	    std::cout << soname << "\n";
	}
    }

    return 0;
}

int
main(int argc, const char *argv[])
{
    process_opts p;
    std::string file_list;
    std::vector<std::string> nonopts;

    cxxopts::Options options(argv[0], "A program to clear or replace rpaths in binaries\n");

    try
    {
	options
	    .set_width(70)
	    .custom_help("[OPTIONS...] binary_file")
	    .add_options()
	    ("a,add-rpath",     "Add the specified path to the rpath", cxxopts::value<std::string>(p.add_rpath_val))
	    ("c,remove-rpath",  "Clear the binary's rpath", cxxopts::value<bool>(p.clear_mode))
	    ("classify",        "Classify files as ELF or OTHER, one JSON record per path.", cxxopts::value<bool>(p.classify_mode))
	    ("f,files",         "Provide a list of binary files to process", cxxopts::value<std::string>(file_list))
	    ("force-rpath",     "Report/process the obsolete DT_RPATH property, not DT_RUNPATH", cxxopts::value<bool>(p.force_rpath))
	    ("print-rpath",     "Print the value of the rpath", cxxopts::value<bool>(p.print_rpath))
	    ("report-rpath-changes", "Report changed rpath entries as tab-separated path, before, and after fields.", cxxopts::value<bool>(p.report_rpath_changes))
	    ("set-rpath-if-needed", "With --set-rpath, update only files with empty rpath or an rpath entry matching --stale-rpath-prefix.", cxxopts::value<bool>(p.set_rpath_if_needed))
	    ("set-rpath-if-needed-append", "In --set-rpath-if-needed mode, place --set-rpath entries after preserved non-stale rpath entries. This is the default.", cxxopts::value<bool>(p.set_rpath_if_needed_append))
	    ("set-rpath-if-needed-prepend", "In --set-rpath-if-needed mode, place --set-rpath entries before preserved non-stale rpath entries.", cxxopts::value<bool>(p.set_rpath_if_needed_prepend))
	    ("s,set-rpath",     "Set rpath to the specified path, clearing existing values", cxxopts::value<std::string>(p.set_rpath_val))
	    ("stale-rpath-prefix", "Path prefix that makes an existing rpath stale in --set-rpath-if-needed mode. May be repeated or comma-separated.", cxxopts::value<std::vector<std::string>>(p.stale_rpath_prefixes))
	    ("print-soname",    "Print the DT_SONAME value (empty if not set)", cxxopts::value<bool>(p.print_soname))
	    ("set-soname",      "Set (or replace) the DT_SONAME value", cxxopts::value<std::string>(p.set_soname_val))
	    ("remove-soname",   "Remove the DT_SONAME entry", cxxopts::value<bool>(p.remove_soname))
	    ("v,verbose",       "Enable verbose reporting during processing.  Multiple specifications of -v increase reporting level, up to a maximum of 5.")
	    ("h,help",          "Print help")
	    ;
	auto result = options.parse(argc, argv);

	nonopts = result.unmatched();

	if (result.count("help")) {
	    std::cout << options.help({""}) << std::endl;
	    std::cout << "\n";
	    std::cout << "Default no-options behavior is to print DT_RUNPATH." << "\n\n";
	    std::cout << "Returns -1 if unable to parse the supplied file." << "\n\n";
	    std::cout << "When --files is supplied, each line of the file is processed as an input path." << "\n\n";
	    std::cout << "When --classify is supplied, outputs one JSON record per path." << "\n\n";
	    std::cout << "When --report-rpath-changes is supplied, outputs only changed files as tab-separated path, before, and after fields." << "\n\n";
	    std::cout << "When --set-rpath-if-needed is supplied with --set-rpath, only empty rpaths and rpaths matching --stale-rpath-prefix values are changed." << "\n";
	    std::cout << "Non-stale rpath entries are preserved, and --set-rpath entries are appended by default unless --set-rpath-if-needed-prepend is supplied." << "\n\n";
	    std::cout << "If both modification and printing options are supplied, values reported" << "\n";
	    std::cout << "will represent post-processing values.  If both a clear and an add are" << "\n";
	    std::cout << "specified, the clear will be performed first." << "\n";
	    return 0;
	}

	if (p.add_rpath_val.length() && p.set_rpath_val.length()) {
	    std::cerr << "Both add-rpath and set-rpath supplied as arguments.\n";
	    return -2;
	}
	if (p.set_rpath_if_needed && !p.set_rpath_val.length()) {
	    std::cerr << "set-rpath-if-needed requires set-rpath.\n";
	    return -2;
	}
	if (p.set_rpath_if_needed_append && p.set_rpath_if_needed_prepend) {
	    std::cerr << "set-rpath-if-needed-append and set-rpath-if-needed-prepend are mutually exclusive.\n";
	    return -2;
	}
	if ((p.set_rpath_if_needed_append || p.set_rpath_if_needed_prepend) && !p.set_rpath_if_needed) {
	    std::cerr << "set-rpath-if-needed append/prepend options require set-rpath-if-needed.\n";
	    return -2;
	}
	if (p.stale_rpath_prefixes.size() && !p.set_rpath_if_needed) {
	    std::cerr << "stale-rpath-prefix requires set-rpath-if-needed.\n";
	    return -2;
	}
	if (p.classify_mode && (p.add_rpath_val.length() || p.set_rpath_val.length() || p.clear_mode || p.remove_soname || p.set_soname_val.length() || p.print_rpath || p.print_soname || p.report_rpath_changes || p.set_rpath_if_needed || p.set_rpath_if_needed_append || p.set_rpath_if_needed_prepend || p.stale_rpath_prefixes.size())) {
	    std::cerr << "Classification mode cannot be combined with modification or print options.\n";
	    return -2;
	}

	// Multiple verbosity settings increase output levels
	p.verbose = result.count("verbose");

    }

    catch (const cxxopts::exceptions::exception& e)
    {
	std::cerr << "error parsing options: " << e.what() << std::endl;
	return -1;
    }

    if (file_list.length() && nonopts.size()) {
	std::cerr << "Error:  specify either --files or one binary file, not both\n";
	return -1;
    }

    if (!file_list.length() && nonopts.size() != 1 && !p.classify_mode) {
	std::cerr << "Error:  need to specify a binary file to process\n";
	return -1;
    }
    if (!file_list.length() && p.classify_mode && nonopts.empty()) {
	std::cerr << "Error:  classification mode needs at least one binary file to process\n";
	return -1;
    }

    LIEF::logging::set_level(LIEF::logging::LEVEL::CRITICAL);
    switch (p.verbose) {
	case 1:
	    LIEF::logging::set_level(LIEF::logging::LEVEL::ERR);
	    break;
	case 2:
	    LIEF::logging::set_level(LIEF::logging::LEVEL::WARN);
	    break;
	case 3:
	    LIEF::logging::set_level(LIEF::logging::LEVEL::INFO);
	    break;
	case 4:
	    LIEF::logging::set_level(LIEF::logging::LEVEL::DEBUG);
	    break;
	case 5:
	    LIEF::logging::set_level(LIEF::logging::LEVEL::TRACE);
	    break;
	default:
	    LIEF::logging::set_level(LIEF::logging::LEVEL::CRITICAL);
    };

    if (p.stale_rpath_prefixes.size())
	p.stale_rpath_prefixes = expand_path_forms(p.stale_rpath_prefixes);

    if (file_list.length()) {
	std::ifstream instream(file_list);
	if (!instream.is_open()) {
	    std::cerr << "Error: Could not open " << file_list << "\n";
	    return -1;
	}
	p.list_output = true;
	int ret = 0;
	std::string line;
	while (std::getline(instream, line)) {
	    if (!line.length())
		continue;
	    if (process_file(line, p))
		ret = -1;
	}
	return ret;
    }

    if (p.classify_mode) {
	int ret = 0;
	for (const auto &fname : nonopts) {
	    if (process_file(fname, p))
		ret = -1;
	}
	return ret;
    }

    return process_file(nonopts[0], p);
}

// Local Variables:
// tab-width: 8
// mode: C++
// c-basic-offset: 4
// indent-tabs-mode: t
// c-file-style: "stroustrup"
// End:
// ex: shiftwidth=4 tabstop=8
