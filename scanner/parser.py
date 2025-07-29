import os
import json
import xml.etree.ElementTree as ET

def parse_requirements(file_path="requirements.txt"):
    deps = []
    if not os.path.exists(file_path):
        return deps
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if '==' in line:
                name, version = line.split('==')
                deps.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return deps

def parse_package_lock(file_path="package-lock.json"):
    deps = []
    if not os.path.exists(file_path):
        return deps
    data = json.load(open(file_path))
    def recurse(dep_dict):
        for name, info in dep_dict.items():
            version = info.get("version")
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
            if "dependencies" in info:
                recurse(info["dependencies"])
    recurse(data.get("dependencies", {}))
    return deps

def parse_pom(file_path="pom.xml"):
    deps = []
    if not os.path.exists(file_path):
        return deps
    tree = ET.parse(file_path)
    root = tree.getroot()
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    for dep in root.findall(".//m:dependency", ns):
        group = dep.find("m:groupId", ns).text
        artifact = dep.find("m:artifactId", ns).text
        version = dep.find("m:version", ns).text
        purl = f"pkg:maven/{group}/{artifact}@{version}"
        deps.append({"purl": purl})
    return deps

def parse_project():
    # Detect which manifest to parse
    if os.path.exists("test-requirements.txt"):
        return parse_requirements("test-requirements.txt")
    if os.path.exists("requirements.txt"):
        return parse_requirements("requirements.txt")
    if os.path.exists("package-lock.json"):
        return parse_package_lock("package-lock.json")
    if os.path.exists("pom.xml"):
        return parse_pom("pom.xml")
    raise FileNotFoundError("No supported manifest file found.")
