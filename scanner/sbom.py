import os
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import get_instance, OutputFormat

def generate_sbom(dependencies, output_path='sbom.json'):
    """
    Generate a CycloneDX SBOM from a list of dependencies and write it to disk,
    unless one already exists at `output_path`.

    :param dependencies: Iterable of objects with .name, .version, and optional .purl attributes
    :param output_path: Where to write the SBOM (default: sbom.json)
    :return: The SBOM as a string (either newly generated or existing)
    """
    # 0) If SBOM already exists, read and return it instead of regenerating
    if os.path.exists(output_path):
        print(f"✔️ SBOM already exists at {output_path}, skipping regeneration.")
        with open(output_path, 'r', encoding='utf-8') as f:
            return f.read()

    # 1) Create an empty BOM
    bom = Bom()

    # 2) Add each dependency as a component
    for dep in dependencies:
        comp = Component(
            name=dep.name,
            version=dep.version,
            type=ComponentType.LIBRARY,
            purl=getattr(dep, 'purl', None)
        )
        bom.add_component(comp)

    # 3) Serialize to JSON (or OutputFormat.XML)
    outputter = get_instance(bom, output_format=OutputFormat.JSON)
    sbom_str = outputter.output_as_string()

    # 4) Write it out
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(sbom_str)

    print(f"✔️ Generated new SBOM at {output_path}")
    return sbom_str
