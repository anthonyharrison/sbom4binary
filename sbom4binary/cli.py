# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from bids.analyser import BIDSAnalyser
from lib4sbom.data.document import SBOMDocument
from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM

from sbom4binary.generator import SBOMBinaryGenerator
from sbom4binary.version import VERSION

# CLI processing


def main(argv=None):
    argv = argv or sys.argv
    app_name = "sbom4binary"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            sbom4binary generates a SBOM from a binary in ELF format.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="Name of binary file",
    )
    input_group.add_argument(
        "--description",
        action="store",
        default="",
        help="description of file",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )

    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: spdx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="specify format of software bill of materials (sbom) (default: tag)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "description": "",
        "output_file": "",
        "sbom": "spdx",
        "debug": False,
        "format": "tag",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    input_file = args["input_file"]

    if input_file == "":
        print("[ERROR] Name of binray file must be specified.")
        return -1

    if args["debug"]:
        print("Input file", args["input_file"])
        print("Description", args["description"])
        print("Output file", args["output_file"])

    options = {
        "dependency": False,
        "symbol": False,
        "callgraph": False,
    }

    analyser = BIDSAnalyser(
        options, description=args["description"], debug=args["debug"]
    )
    try:
        # Analyse file
        analyser.analyse(input_file)
        if args["debug"]:
            print(f"Dependencies: {analyser.get_dependencies()}")
            print(f"Imports: {analyser.get_global_symbols()}")
            print(f"Exports: {sorted(analyser.get_local_symbols())}")
    except TypeError:
        print("[ERROR] Only ELF files can be analysed.")
        return -2
    except FileNotFoundError:
        print(f"[ERROR] {input_file} not found.")
        return -1

    generator = SBOMBinaryGenerator(debug=args["debug"])

    # Create SBOM data
    sbom_packages, sbom_relationships = generator.create_sbom(analyser)
    # Generate SBOM
    binary_sbom = SBOM()
    binary_sbom.set_type(sbom_type=args["sbom"])
    binary_doc = SBOMDocument()
    binary_doc.set_value("lifecycle", "build")
    binary_sbom.add_document(binary_doc.get_document())
    binary_sbom.add_packages(sbom_packages)
    binary_sbom.add_relationships(sbom_relationships)
    sbom_generator = SBOMGenerator(
        False,
        sbom_type=args["sbom"],
        format=args["format"],
        application=app_name,
        version=VERSION,
    )
    sbom_generator.generate(
        project_name=generator.get_project(),
        sbom_data=binary_sbom.get_sbom(),
        filename=args["output_file"],
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
