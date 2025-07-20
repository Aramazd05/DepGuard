from cyclonedx.model.bom import Bom
from cyclonedx.output import get_instance

def generate_sbom():
    bom = Bom()
    outputter = get_instance(bom, 'json')
    return outputter.output_as_string()
