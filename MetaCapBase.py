

class MetaCapBase(object):

    def __init__(self, base_location):
       self.packetBase = []
       self.base_loc = base_location

    def add_lib_to_base(self, newMetaCapLib):
        self.packetBase.append(newMetaCapLib)

    def set_base_location(self, base_location):
        self.base_loc = base_location
        return