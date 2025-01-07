# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from pathlib import PurePosixPath

from bids.output import BIDSOutput
from bids.version import VERSION
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship


class SBOMBinaryGenerator:

    def __init__(self, debug=False):
        self.debug = debug
        self.appname = "Binary"

    def create_sbom(self, analyser):

        output = BIDSOutput(tool_version=VERSION)
        output.create_metadata(analyser.get_file_data())
        output.create_components(
            analyser.get_dependencies(),
            analyser.get_global_symbols(),
            analyser.get_callgraph(),
            local=analyser.get_local_symbols(),
        )
        data = output.get_document()

        if self.debug:
            print(data)
        sbom_packages = {}
        sbom_relationships = []
        # Create parent package
        binary_package = SBOMPackage()
        binary_package.set_type("application")
        filename = PurePosixPath(data["metadata"]["binary"]["filename"]).name
        # print (PurePosixPath(filename).name)
        binary_package.set_name(str(filename))
        # binary_package.set_name(data["metadata"]["binary"]["filename"])
        binary_package.set_value("release_date", data["metadata"]["binary"]["filedate"])
        binary_package.set_evidence(data["metadata"]["binary"]["filename"])
        # Add evidence details relating to filename and filesize
        checksum_algorithm = data["metadata"]["binary"]["checksum"]["algorithm"]
        checksum = data["metadata"]["binary"]["checksum"]["value"]
        binary_package.set_checksum(checksum_algorithm, checksum)
        for property in ["class", "architecture", "bits", "os"]:
            binary_package.set_property(property, data["metadata"]["binary"][property])
        if "description" in data["metadata"]["binary"]:
            binary_package.set_description(data["metadata"]["binary"]["description"])
            self.appname = data["metadata"]["binary"]["description"].replace(" ", "_")
        sbom_packages[
            (binary_package.get_name(), binary_package.get_value("version"))
        ] = binary_package.get_package()

        # Create relationship for application
        if self.debug:
            print(f"Appname: {self.appname}")
        dependency_relationship = SBOMRelationship()
        dependency_relationship.set_relationship(
            self.appname, "DESCRIBES", binary_package.get_name()
        )
        sbom_relationships.append(dependency_relationship.get_relationship())

        # Now look at dependencies
        for library in data["components"]["dynamiclibrary"]:
            # Create package
            dependency_package = SBOMPackage()
            dependency_package.set_type("library")
            dependency_package.set_name(library["name"])
            dependency_package.set_evidence(library["location"])
            if "version" in library:
                dependency_package.set_value("version", library["version"])
            sbom_packages[
                (dependency_package.get_name(), dependency_package.get_value("version"))
            ] = dependency_package.get_package()

            # Create relationship with parent application
            dependency_relationship = SBOMRelationship()
            dependency_relationship.set_relationship(
                binary_package.get_name(), "DEPENDS_ON", dependency_package.get_name()
            )
            sbom_relationships.append(dependency_relationship.get_relationship())

        return sbom_packages, sbom_relationships

    def get_project(self):
        return self.appname
