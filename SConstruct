#!/usr/bin/env python
import os
import sys

# Initialize the environment from godot-cpp
env = SConscript("godot-cpp/SConstruct")

# Add source files
env.Append(CPPPATH=["src/"])
sources = Glob("src/*.cpp")

# Android-specific NDK setup
if env["platform"] == "android":
    # Ensure Android NDK is set up
    if "ANDROID_NDK_ROOT" in os.environ:
        env["ANDROID_NDK_ROOT"] = os.environ["ANDROID_NDK_ROOT"]

# Build the shared library
library_name = "websocket_server{}{}".format(env["suffix"], env["SHLIBSUFFIX"])
library = env.SharedLibrary(
    target="bin/" + library_name,
    source=sources,
)

Default(library)

# Print build info for debugging
print(f"Building for platform: {env['platform']}")
print(f"Target architecture: {env.get('arch', 'default')}")
print(f"Library will be: bin/{library_name}")