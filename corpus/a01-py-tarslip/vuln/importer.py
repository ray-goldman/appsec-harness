import tarfile

def import_bundle(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest)
