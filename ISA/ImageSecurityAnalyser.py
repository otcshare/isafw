# main class of Image Security Analyser
import os
import sys
import imp
import plugins

# class for representing a package for ISA plugins

class ISA_package:
    name = ""                     # pkg name (mandatory argument)
    version = ""                  # full version
    licenses = []                 # list of licences for all subpackages
    source_files = []             # list of strings of source files (tarball, patches, spec)
    path_to_sources = ""          # path to the source files (mandatory argument)

class ImageSecurityAnalyser:
    def __init__(self):
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
                # see if the plugin has a 'init' attribute
                register_plugin = plugin.init
            except:
                print("Error in calling init() for plugin " + plugin.getPluginName())
                print("Error info: ", sys.exc_info())
                print("Skipping this plugin")
                continue           
            else:
                try:
                    register_plugin()
                except:
                    print("Exception in plugin init: ", sys.exc_info())

    def process_package_source(self, ISA_package):
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
                # see if the plugin has a 'process_package_source' attribute
                process_package_source = plugin.process_package_source
            except AttributeError:
                # if it doesn't, it is ok, won't call this plugin
                pass
            else:
                try:
                    process_package_source(ISA_package)
                except:
                    print("Exception in plugin: ", sys.exc_info())

    def process_package_list(self, package_list):
        # print package_list
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
                # see if the plugin has a 'process_package_list' attribute
                process_package_list = plugin.process_package_list
            except AttributeError:
                # if it doesn't, it is ok, won't call this plugin
                pass
            else:
                try:
                    process_package_list(package_list)
                except:
                    print("Exception in plugin: ", sys.exc_info())

    def process_fsroot(self, fsroot_path):
        # print fsroot_path
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
                # see if the plugin has a 'process_fsroot' attribute
                process_fsroot = plugin.process_fsroot
            except AttributeError:
                # if it doesn't, it is ok, won't call this plugin
                pass
            else:
                try:
                    process_fsroot(fsroot_path)
                except:
                    print("Exception in plugin: ", sys.exc_info())




