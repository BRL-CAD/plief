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
    size_t verbose = 0;
    std::string add_rpath_val;
    std::string set_rpath_val;
    std::string set_soname_val;
    bool list_output = false;
};

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

    if (p.clear_mode) {
	if (p.force_rpath) {
	    binfo->remove(LIEF::ELF::DynamicEntry::TAG::RPATH);
	} else {
	    binfo->remove(LIEF::ELF::DynamicEntry::TAG::RUNPATH);
	}
	bin_mod = true;
    }


    if (p.add_rpath_val.length()) {

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

    if (p.set_rpath_val.length()) {

	// set-rpath is destructive - clear the old value and add the new
	if (p.force_rpath) {
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

    // Write out the new version of the binary
    if (bin_mod)
	binfo->write(fname);

    if (p.print_rpath || (!bin_mod && !p.print_soname)) {
	// Doing the lookup here to make sure we have the current, valid binfo
	// entries for printing
	LIEF::ELF::DynamicEntry *rp = (p.force_rpath) ?  binfo->get(LIEF::ELF::DynamicEntry::TAG::RPATH) : binfo->get(LIEF::ELF::DynamicEntry::TAG::RUNPATH);
	std::vector<std::string> paths;
	if (rp) {
	    if (!p.force_rpath) {
		paths = reinterpret_cast<LIEF::ELF::DynamicEntryRunPath*>(rp)->paths();
	    } else {
		paths = reinterpret_cast<LIEF::ELF::DynamicEntryRpath*>(rp)->paths();
	    }
	}
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
	LIEF::ELF::DynamicEntry *so = binfo->get(LIEF::ELF::DynamicEntry::TAG::SONAME);
	if (so) {
	    if (p.list_output)
		std::cout << fname << ":";
	    std::cout << reinterpret_cast<LIEF::ELF::DynamicSharedObject*>(so)->name() << "\n";
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
	    ("s,set-rpath",     "Set rpath to the specified path, clearing existing values", cxxopts::value<std::string>(p.set_rpath_val))
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
	    std::cout << "If both modification and printing options are supplied, values reported" << "\n";
	    std::cout << "will represent post-processing values.  If both a clear and an add are" << "\n";
	    std::cout << "specified, the clear will be performed first." << "\n";
	    return 0;
	}

	if (p.add_rpath_val.length() && p.set_rpath_val.length()) {
	    std::cerr << "Both add-rpath and set-rpath supplied as arguments.\n";
	    return -2;
	}
	if (p.classify_mode && (p.add_rpath_val.length() || p.set_rpath_val.length() || p.clear_mode || p.remove_soname || p.set_soname_val.length() || p.print_rpath || p.print_soname)) {
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
