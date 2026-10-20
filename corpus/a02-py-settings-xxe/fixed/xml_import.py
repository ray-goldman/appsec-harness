from defusedxml.lxml import fromstring

def load(data):
    return fromstring(data)
