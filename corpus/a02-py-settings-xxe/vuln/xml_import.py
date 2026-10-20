from lxml import etree
parser = etree.XMLParser(resolve_entities=True)

def load(data):
    return etree.fromstring(data, parser)
