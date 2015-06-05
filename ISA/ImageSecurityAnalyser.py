# main class of Image Security Analyser
import os
import sys
import imp
import plugins

# class for representing a package for ISA plugins

class ISA_package:
    name = ""                     # pkg name (mandatory argument)
    version = ""                  # full version
    licenses = ""                 # commaseparated string of licences for all subpackages
    source_files = []             # array of strings of source files (tarball, patches, spec)
    path_to_sources = ""          # path to the source files (mandatory argument)

class ImageSecurityAnalyser:
    def __init__(self):
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                register_plugin = plugin.init
            except AttributeError:
                print("Error in calling init() for plugin " + plugin.getPluginName())
            else:
                 # try to call it, without catching any errors
                 register_plugin()

    def process_package_source(self, ISA_package):
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                process_package_source = plugin.process_package_source
            except AttributeError:
                pass
            else:
                 # try to call it, without catching any errors
                 process_package_source(ISA_package)

    def process_package_list(self, package_list):
        #print package_list
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                process_package_list = plugin.process_package_list
            except AttributeError:
                pass
            else:
                 # try to call it, without catching any errors
                 process_package_list(package_list)

    def process_fsroot(self, fsroot_path):
        #print fsroot_path
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                process_fsroot = plugin.process_fsroot
            except AttributeError:
                pass
            else:
                 # try to call it, without catching any errors
                 process_fsroot(fsroot_path)




