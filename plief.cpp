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

#include <iostream>
#include <string>
#include <vector>
#include "cxxopts.hpp"
#include "LIEF/ELF.hpp"
#include "LIEF/logging.hpp"

int
main(int argc, const char *argv[])
{
    bool clear_mode = false;
    bool print_rpath = false;
    bool force_rpath = false; // To manipulate DT_RPATH rather than DT_RUNPATH
    size_t verbose = 0;
    std::string add_rpath_val;
    std::string set_rpath_val;
    std::vector<std::string> nonopts;

    cxxopts::Options options(argv[0], "A program to clear or replace rpaths in binaries\n");

    try
    {
	options
	    .set_width(70)
	    .custom_help("[OPTIONS...] binary_file")
	    .add_options()
	    ("a,add-rpath",    "Add the specified path to the rpath", cxxopts::value<std::string>(add_rpath_val))
	    ("c,remove-rpath", "Clear the binary's rpath", cxxopts::value<bool>(clear_mode))
	    ("force-rpath",    "Report/process the obsolete DT_RPATH property, not DT_RUNPATH", cxxopts::value<bool>(force_rpath))
	    ("print-rpath",    "Print the value of the rpath", cxxopts::value<bool>(print_rpath))
	    ("s,set-rpath",    "Set rpath to the specified path, clearing existing values", cxxopts::value<std::string>(set_rpath_val))
	    ("v,verbose",      "Enable verbose reporting during processing.  Multiple specifications of -v increase reporting level, up to a maximum of 5.")
	    ("h,help",         "Print help")
	    ;
	auto result = options.parse(argc, argv);

	nonopts = result.unmatched();

	if (result.count("help")) {
	    std::cout << options.help({""}) << std::endl;
	    std::cout << "\n";
	    std::cout << "Default no-options behavior is to print DT_RUNPATH." << "\n\n";
	    std::cout << "Returns -1 if unable to parse the supplied file." << "\n\n";
	    std::cout << "If both modification and printing options are supplied, values reported" << "\n";
	    std::cout << "will represent post-processing values.  If both a clear and an add are" << "\n";
	    std::cout << "specified, the clear will be performed first." << "\n";
	    return 0;
	}

	if (add_rpath_val.length() && set_rpath_val.length()) {
	    std::cerr << "Both add-rpath and set-rpath supplied as arguments.\n";
	    return -2;
	}

	// Multiple verbosity settings increase output levels
	verbose = result.count("verbose");

    }

    catch (const cxxopts::exceptions::exception& e)
    {
	std::cerr << "error parsing options: " << e.what() << std::endl;
	return -1;
    }

    if (nonopts.size() != 1) {
	std::cerr << "Error:  need to specify a binary file to process\n";
	return -1;
    }

    bool bin_mod = false;
    LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_CRITICAL);
    switch (verbose) {
	case 1:
	    LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_ERR);
	    break;
	case 2:
	    LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_WARN);
	    break;
	case 3:
	    LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_INFO);
	    break;
	case 4:
	    LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_DEBUG);
	    break;
	case 5:
	    LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_TRACE);
	    break;
	default:
	    LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_CRITICAL);
    };

    std::unique_ptr<LIEF::ELF::Binary> binfo = std::unique_ptr<LIEF::ELF::Binary>{LIEF::ELF::Parser::parse(nonopts[0])};
    if (!binfo) {
	std::cerr << "Not an ELF file\n";
	return -1;
    }

    if (clear_mode) {
	if (force_rpath) {
	    binfo->remove(LIEF::ELF::DYNAMIC_TAGS::DT_RPATH);
	} else {
	    binfo->remove(LIEF::ELF::DYNAMIC_TAGS::DT_RUNPATH);
	}
	bin_mod = true;
    }


    if (add_rpath_val.length()) {

	// Adding a path is not destructive to existing RUNPATH values, so we have
	// to generate a composite if previous data exists.
	std::string opath;
	LIEF::ELF::DynamicEntry *rp = (force_rpath) ?  binfo->get(LIEF::ELF::DYNAMIC_TAGS::DT_RPATH) : binfo->get(LIEF::ELF::DYNAMIC_TAGS::DT_RUNPATH);
	if (rp) {
	    if (force_rpath) {
		opath.append(reinterpret_cast<LIEF::ELF::DynamicEntryRpath*>(rp)->name());
	    } else {
		opath.append(reinterpret_cast<LIEF::ELF::DynamicEntryRunPath*>(rp)->name());
	    }
	}
	if (opath.length())
	    opath.append(std::string(":"));
	opath.append(add_rpath_val);

	// Clear any old path objects and add the new
	if (force_rpath) {
	    binfo->remove(LIEF::ELF::DYNAMIC_TAGS::DT_RPATH);
	    LIEF::ELF::DynamicEntryRpath npe(opath);
	    binfo->add(npe);
	} else {
	    binfo->remove(LIEF::ELF::DYNAMIC_TAGS::DT_RUNPATH);
	    LIEF::ELF::DynamicEntryRunPath npe(opath);
	    binfo->add(npe);
	}

	bin_mod = true;

    }

    if (set_rpath_val.length()) {

	// set-rpath is destructive - clear the old value and add the new
	if (force_rpath) {
	    binfo->remove(LIEF::ELF::DYNAMIC_TAGS::DT_RPATH);
	    LIEF::ELF::DynamicEntryRpath npe(set_rpath_val);
	    binfo->add(npe);
	} else {
	    binfo->remove(LIEF::ELF::DYNAMIC_TAGS::DT_RUNPATH);
	    LIEF::ELF::DynamicEntryRunPath npe(set_rpath_val);
	    binfo->add(npe);
	}

	bin_mod = true;

    }

    // Write out the new version of the binary
    if (bin_mod)
	binfo->write(nonopts[0]);

    if (!bin_mod || print_rpath) {
	// Doing the lookup here to make sure we have the current, valid binfo
	// entries for printing
	LIEF::ELF::DynamicEntry *rp = (force_rpath) ?  binfo->get(LIEF::ELF::DYNAMIC_TAGS::DT_RPATH) : binfo->get(LIEF::ELF::DYNAMIC_TAGS::DT_RUNPATH);
	if (!force_rpath && rp)
	    std::cout << reinterpret_cast<LIEF::ELF::DynamicEntryRunPath*>(rp)->name() << '\n';
	if (force_rpath && rp)
	    std::cout << reinterpret_cast<LIEF::ELF::DynamicEntryRpath*>(rp)->name() << '\n';
    }

    return 0;
}

// Local Variables:
// tab-width: 8
// mode: C++
// c-basic-offset: 4
// indent-tabs-mode: t
// c-file-style: "stroustrup"
// End:
// ex: shiftwidth=4 tabstop=8

