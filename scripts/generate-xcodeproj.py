#!/usr/bin/env python3
"""Generates WirePath.xcodeproj (Xcode 16+ project format with file-system synchronized folders).

The project only wires targets to folders and local packages, so adding a Swift file to
WirePathMac/, WirePathiPad/ or WirePathTests/ needs no project edit. Re-run after changing targets:

    python3 scripts/generate-xcodeproj.py
"""
import hashlib
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT = os.path.join(ROOT, "WirePath.xcodeproj")

BUNDLE_ID = "com.wirepath.WirePath"
VERSION = "0.2.1"
BUILD = "3"


def oid(name):
    return hashlib.sha1(name.encode()).hexdigest()[:24].upper()


objects = []


def add(identifier, comment, body):
    objects.append((identifier, comment, body))


def settings_block(settings, indent="\t\t\t\t"):
    lines = []
    for key in sorted(settings):
        value = settings[key]
        if isinstance(value, list):
            items = "".join(f"\n{indent}\t{quote(v)}," for v in value)
            lines.append(f"{indent}{key} = ({items}\n{indent});")
        else:
            lines.append(f"{indent}{key} = {quote(value)};")
    return "\n".join(lines)


def quote(value):
    value = str(value)
    if value and all(c.isalnum() or c in "._/" for c in value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


project_id = oid("project")
main_group = oid("group.main")
products_group = oid("group.products")
core_pkg = oid("pkg.core")
ui_pkg = oid("pkg.ui")

common_debug = {
    "ALWAYS_SEARCH_USER_PATHS": "NO",
    "CLANG_ENABLE_MODULES": "YES",
    "CLANG_ENABLE_OBJC_ARC": "YES",
    "COPY_PHASE_STRIP": "NO",
    "DEBUG_INFORMATION_FORMAT": "dwarf",
    "ENABLE_STRICT_OBJC_MSGSEND": "YES",
    "ENABLE_TESTABILITY": "YES",
    "ENABLE_USER_SCRIPT_SANDBOXING": "YES",
    "GCC_OPTIMIZATION_LEVEL": "0",
    "LOCALIZATION_PREFERS_STRING_CATALOGS": "YES",
    "MTL_ENABLE_DEBUG_INFO": "INCLUDE_SOURCE",
    "ONLY_ACTIVE_ARCH": "YES",
    "SWIFT_ACTIVE_COMPILATION_CONDITIONS": "DEBUG $(inherited)",
    "SWIFT_EMIT_LOC_STRINGS": "YES",
    "SWIFT_OPTIMIZATION_LEVEL": "-Onone",
    "SWIFT_VERSION": "6.0",
}
common_release = dict(common_debug)
common_release.update({
    # Release builds never carry com.apple.security.get-task-allow (Xcode adds it for development signing), which
    # notarization rejects and which would let other processes attach to WirePath.
    "CODE_SIGN_INJECT_BASE_ENTITLEMENTS": "NO",
    "DEBUG_INFORMATION_FORMAT": "dwarf-with-dsym",
    "ENABLE_TESTABILITY": "NO",
    "GCC_OPTIMIZATION_LEVEL": "s",
    "MTL_ENABLE_DEBUG_INFO": "NO",
    "ONLY_ACTIVE_ARCH": "NO",
    "SWIFT_ACTIVE_COMPILATION_CONDITIONS": "$(inherited)",
    "SWIFT_COMPILATION_MODE": "wholemodule",
    "SWIFT_OPTIMIZATION_LEVEL": "-O",
    "VALIDATE_PRODUCT": "YES",
})

mac_settings = {
    "ARCHS": "arm64",
    "ASSETCATALOG_COMPILER_APPICON_NAME": "AppIcon",
    "CODE_SIGN_ENTITLEMENTS": "WirePathMac/WirePathMac.entitlements",
    "CODE_SIGN_IDENTITY": "-",
    "CODE_SIGN_STYLE": "Automatic",
    "COMBINE_HIDPI_IMAGES": "YES",
    "CURRENT_PROJECT_VERSION": BUILD,
    "ENABLE_HARDENED_RUNTIME": "YES",
    "GENERATE_INFOPLIST_FILE": "YES",
    "INFOPLIST_FILE": "WirePathMac/Info.plist",
    "INFOPLIST_KEY_CFBundleDisplayName": "WirePath",
    "INFOPLIST_KEY_LSApplicationCategoryType": "public.app-category.developer-tools",
    "INFOPLIST_KEY_NSHumanReadableCopyright": "WirePath — offline capture analyzer",
    "LD_RUNPATH_SEARCH_PATHS": ["$(inherited)", "@executable_path/../Frameworks"],
    "MACOSX_DEPLOYMENT_TARGET": "15.0",
    "MARKETING_VERSION": VERSION,
    "PRODUCT_BUNDLE_IDENTIFIER": BUNDLE_ID,
    "PRODUCT_NAME": "WirePath",
    "SDKROOT": "macosx",
    "SUPPORTED_PLATFORMS": "macosx",
    "SWIFT_EMIT_LOC_STRINGS": "YES",
}

ipad_settings = {
    "ASSETCATALOG_COMPILER_APPICON_NAME": "AppIcon",
    "CODE_SIGN_STYLE": "Automatic",
    "CURRENT_PROJECT_VERSION": BUILD,
    "GENERATE_INFOPLIST_FILE": "YES",
    "INFOPLIST_FILE": "WirePathiPad/Info.plist",
    "INFOPLIST_KEY_CFBundleDisplayName": "WirePath",
    "INFOPLIST_KEY_LSApplicationCategoryType": "public.app-category.developer-tools",
    "INFOPLIST_KEY_UIApplicationSupportsIndirectInputEvents": "YES",
    "INFOPLIST_KEY_UILaunchScreen_Generation": "YES",
    "INFOPLIST_KEY_UISupportedInterfaceOrientations_iPad": "UIInterfaceOrientationPortrait UIInterfaceOrientationPortraitUpsideDown UIInterfaceOrientationLandscapeLeft UIInterfaceOrientationLandscapeRight",
    "IPHONEOS_DEPLOYMENT_TARGET": "18.0",
    "LD_RUNPATH_SEARCH_PATHS": ["$(inherited)", "@executable_path/Frameworks"],
    "MARKETING_VERSION": VERSION,
    "PRODUCT_BUNDLE_IDENTIFIER": BUNDLE_ID,
    "PRODUCT_NAME": "WirePath",
    "SDKROOT": "iphoneos",
    "SUPPORTED_PLATFORMS": "iphoneos iphonesimulator",
    "SUPPORTS_MACCATALYST": "NO",
    "SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD": "NO",
    "SUPPORTS_XR_DESIGNED_FOR_IPHONE_IPAD": "NO",
    "TARGETED_DEVICE_FAMILY": "2",
}

mac_uitest_settings = {
    "ARCHS": "arm64",
    "CODE_SIGN_IDENTITY": "-",
    "CODE_SIGN_STYLE": "Automatic",
    "GENERATE_INFOPLIST_FILE": "YES",
    "MACOSX_DEPLOYMENT_TARGET": "15.0",
    "PRODUCT_BUNDLE_IDENTIFIER": BUNDLE_ID + ".MacUITests",
    "PRODUCT_NAME": "$(TARGET_NAME)",
    "SDKROOT": "macosx",
    "TEST_TARGET_NAME": "WirePathMac",
}

ipad_uitest_settings = {
    "CODE_SIGN_STYLE": "Automatic",
    "GENERATE_INFOPLIST_FILE": "YES",
    "IPHONEOS_DEPLOYMENT_TARGET": "18.0",
    "PRODUCT_BUNDLE_IDENTIFIER": BUNDLE_ID + ".iPadUITests",
    "PRODUCT_NAME": "$(TARGET_NAME)",
    "SDKROOT": "iphoneos",
    "SUPPORTED_PLATFORMS": "iphoneos iphonesimulator",
    "TARGETED_DEVICE_FAMILY": "2",
    "TEST_TARGET_NAME": "WirePathiPad",
}

targets = [
    # name, folder, product file, product type, explicit type, settings, packages, test host
    ("WirePathMac", "WirePathMac", "WirePath.app", "com.apple.product-type.application", "wrapper.application",
     mac_settings, ["WirePathCore", "WirePathUI"], None,
     ["Info.plist", "WirePathMac.entitlements", "WirePathMac.Debug.entitlements"]),
    ("WirePathiPad", "WirePathiPad", "WirePath.app", "com.apple.product-type.application", "wrapper.application",
     ipad_settings, ["WirePathCore", "WirePathUI"], None, ["Info.plist"]),
    ("WirePathMacUITests", "WirePathTests/MacUITests", "WirePathMacUITests.xctest", "com.apple.product-type.bundle.ui-testing",
     "wrapper.cfbundle", mac_uitest_settings, [], "WirePathMac", []),
    ("WirePathiPadUITests", "WirePathTests/iPadUITests", "WirePathiPadUITests.xctest", "com.apple.product-type.bundle.ui-testing",
     "wrapper.cfbundle", ipad_uitest_settings, [], "WirePathiPad", []),
]

# Per-configuration overrides. Release (what ships) runs in the App Sandbox; Debug leaves it off so UI tests,
# snapshot mode and WIREPATH_IMPORT can read fixtures anywhere on disk. See docs/architecture.md.
config_overrides = {
    ("WirePathMac", "Debug"): {"CODE_SIGN_ENTITLEMENTS": "WirePathMac/WirePathMac.Debug.entitlements"},
}

# Folders shared by several targets: the string catalog (English, Spanish) ships in both apps, where SwiftUI and
# String(localized:) look strings up (Bundle.main), including those of the WirePathCore and WirePathUI packages;
# so does the privacy manifest (docs/release.md).
shared_folders = {"Localization": ["WirePathMac", "WirePathiPad"], "Privacy": ["WirePathMac", "WirePathiPad"]}
for folder in shared_folders:
    add(oid("syncgroup.shared." + folder), folder,
        f"{{\n\t\t\tisa = PBXFileSystemSynchronizedRootGroup;\n\t\t\tpath = {quote(folder)};\n\t\t\tsourceTree = \"<group>\";\n\t\t}}")

product_refs = []
target_ids = {}
for name, folder, product, ptype, explicit, settings, packages, host, exclusions in targets:
    t = oid("target." + name)
    target_ids[name] = t
    group = oid("syncgroup." + name)
    product_ref = oid("product." + name)
    product_refs.append((product_ref, product))
    add(product_ref, product,
        f"{{isa = PBXFileReference; explicitFileType = {explicit}; includeInIndex = 0; path = {product}; sourceTree = BUILT_PRODUCTS_DIR; }}")
    exception = ""
    if exclusions:
        exc_id = oid("exceptions." + name)
        files = "".join(f"\n\t\t\t\t{quote(f)}," for f in exclusions)
        add(exc_id, f'Exceptions for "{folder}" folder in "{name}" target',
            f"{{\n\t\t\tisa = PBXFileSystemSynchronizedBuildFileExceptionSet;\n\t\t\tmembershipExceptions = ({files}\n\t\t\t);\n\t\t\ttarget = {t} /* {name} */;\n\t\t}}")
        exception = f"\n\t\t\texceptions = (\n\t\t\t\t{exc_id} /* Exceptions for \"{folder}\" folder in \"{name}\" target */,\n\t\t\t);"
    add(group, folder,
        f"{{\n\t\t\tisa = PBXFileSystemSynchronizedRootGroup;{exception}\n\t\t\tpath = {quote(folder)};\n\t\t\tsourceTree = \"<group>\";\n\t\t}}")
    sources = oid("sources." + name)
    frameworks = oid("frameworks." + name)
    resources = oid("resources." + name)
    add(sources, "Sources", "{\n\t\t\tisa = PBXSourcesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t}")
    fw_files = []
    product_deps = []
    for package in packages:
        dep = oid(f"productdep.{name}.{package}")
        bf = oid(f"buildfile.{name}.{package}")
        pkg_ref = core_pkg if package == "WirePathCore" else ui_pkg
        add(dep, package, f"{{\n\t\t\tisa = XCSwiftPackageProductDependency;\n\t\t\tpackage = {pkg_ref};\n\t\t\tproductName = {package};\n\t\t}}")
        add(bf, f"{package} in Frameworks", f"{{isa = PBXBuildFile; productRef = {dep} /* {package} */; }}")
        fw_files.append(f"\n\t\t\t\t{bf} /* {package} in Frameworks */,")
        product_deps.append(f"\n\t\t\t\t{dep} /* {package} */,")
    add(frameworks, "Frameworks", "{\n\t\t\tisa = PBXFrameworksBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (" + "".join(fw_files) + "\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t}")
    add(resources, "Resources", "{\n\t\t\tisa = PBXResourcesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t}")
    dependencies = ""
    if host:
        proxy = oid("proxy." + name)
        dep = oid("targetdep." + name)
        add(proxy, "PBXContainerItemProxy", f"{{\n\t\t\tisa = PBXContainerItemProxy;\n\t\t\tcontainerPortal = {project_id} /* Project object */;\n\t\t\tproxyType = 1;\n\t\t\tremoteGlobalIDString = {oid('target.' + host)};\n\t\t\tremoteInfo = {host};\n\t\t}}")
        add(dep, "PBXTargetDependency", f"{{\n\t\t\tisa = PBXTargetDependency;\n\t\t\ttarget = {oid('target.' + host)} /* {host} */;\n\t\t\ttargetProxy = {proxy} /* PBXContainerItemProxy */;\n\t\t}}")
        dependencies = f"\n\t\t\t\t{dep} /* PBXTargetDependency */,"
    configs = []
    for config, base in (("Debug", {}), ("Release", {})):
        cid = oid(f"config.{name}.{config}")
        merged = dict(settings)
        merged.update(config_overrides.get((name, config), {}))
        add(cid, config, f"{{\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {{\n{settings_block(merged)}\n\t\t\t}};\n\t\t\tname = {config};\n\t\t}}")
        configs.append(cid)
    clist = oid("configlist." + name)
    add(clist, f'Build configuration list for PBXNativeTarget "{name}"',
        f"{{\n\t\t\tisa = XCConfigurationList;\n\t\t\tbuildConfigurations = (\n\t\t\t\t{configs[0]} /* Debug */,\n\t\t\t\t{configs[1]} /* Release */,\n\t\t\t);\n\t\t\tdefaultConfigurationIsVisible = 0;\n\t\t\tdefaultConfigurationName = Release;\n\t\t}}")
    shared_groups = "".join(f"\n\t\t\t\t{oid('syncgroup.shared.' + f)} /* {f} */," for f, users in shared_folders.items() if name in users)
    add(t, name, f"{{\n\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {clist} /* Build configuration list for PBXNativeTarget \"{name}\" */;\n\t\t\tbuildPhases = (\n\t\t\t\t{sources} /* Sources */,\n\t\t\t\t{frameworks} /* Frameworks */,\n\t\t\t\t{resources} /* Resources */,\n\t\t\t);\n\t\t\tbuildRules = (\n\t\t\t);\n\t\t\tdependencies = ({dependencies}\n\t\t\t);\n\t\t\tfileSystemSynchronizedGroups = (\n\t\t\t\t{group} /* {folder} */,{shared_groups}\n\t\t\t);\n\t\t\tname = {name};\n\t\t\tpackageProductDependencies = ({''.join(product_deps)}\n\t\t\t);\n\t\t\tproductName = {name};\n\t\t\tproductReference = {product_ref} /* {product} */;\n\t\t\tproductType = \"{ptype}\";\n\t\t}}")

# Groups
children = "".join(f"\n\t\t\t\t{oid('syncgroup.' + t[0])} /* {t[1]} */," for t in targets)
children += "".join(f"\n\t\t\t\t{oid('syncgroup.shared.' + f)} /* {f} */," for f in shared_folders)
add(main_group, "", "{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (" + children + f"\n\t\t\t\t{products_group} /* Products */,\n\t\t\t);\n\t\t\tsourceTree = \"<group>\";\n\t\t}}")
add(products_group, "Products", "{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (" + "".join(f"\n\t\t\t\t{r} /* {p} */," for r, p in product_refs) + "\n\t\t\t);\n\t\t\tname = Products;\n\t\t\tsourceTree = \"<group>\";\n\t\t}")

# Packages
add(core_pkg, 'XCLocalSwiftPackageReference "Packages/WirePathCore"', "{\n\t\t\tisa = XCLocalSwiftPackageReference;\n\t\t\trelativePath = Packages/WirePathCore;\n\t\t}")
add(ui_pkg, 'XCLocalSwiftPackageReference "Packages/WirePathUI"', "{\n\t\t\tisa = XCLocalSwiftPackageReference;\n\t\t\trelativePath = Packages/WirePathUI;\n\t\t}")

# Project configurations
pconfigs = []
for config, base in (("Debug", common_debug), ("Release", common_release)):
    cid = oid("config.project." + config)
    add(cid, config, f"{{\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {{\n{settings_block(base)}\n\t\t\t}};\n\t\t\tname = {config};\n\t\t}}")
    pconfigs.append(cid)
plist = oid("configlist.project")
add(plist, 'Build configuration list for PBXProject "WirePath"', f"{{\n\t\t\tisa = XCConfigurationList;\n\t\t\tbuildConfigurations = (\n\t\t\t\t{pconfigs[0]} /* Debug */,\n\t\t\t\t{pconfigs[1]} /* Release */,\n\t\t\t);\n\t\t\tdefaultConfigurationIsVisible = 0;\n\t\t\tdefaultConfigurationName = Release;\n\t\t}}")

target_attrs = "".join(
    f"\n\t\t\t\t\t{target_ids[t[0]]} = {{\n\t\t\t\t\t\tCreatedOnToolsVersion = 27.0;" + (f"\n\t\t\t\t\t\tTestTargetID = {target_ids[t[7]]};" if t[7] else "") + "\n\t\t\t\t\t};"
    for t in targets)
add(project_id, "Project object", f"{{\n\t\t\tisa = PBXProject;\n\t\t\tattributes = {{\n\t\t\t\tBuildIndependentTargetsInParallel = 1;\n\t\t\t\tLastSwiftUpdateCheck = 2700;\n\t\t\t\tLastUpgradeCheck = 2700;\n\t\t\t\tTargetAttributes = {{{target_attrs}\n\t\t\t\t}};\n\t\t\t}};\n\t\t\tbuildConfigurationList = {plist} /* Build configuration list for PBXProject \"WirePath\" */;\n\t\t\tdevelopmentRegion = en;\n\t\t\thasScannedForEncodings = 0;\n\t\t\tknownRegions = (\n\t\t\t\ten,\n\t\t\t\tes,\n\t\t\t\tBase,\n\t\t\t);\n\t\t\tmainGroup = {main_group};\n\t\t\tminimizedProjectReferenceProxies = 1;\n\t\t\tpackageReferences = (\n\t\t\t\t{core_pkg} /* XCLocalSwiftPackageReference \"Packages/WirePathCore\" */,\n\t\t\t\t{ui_pkg} /* XCLocalSwiftPackageReference \"Packages/WirePathUI\" */,\n\t\t\t);\n\t\t\tpreferredProjectObjectVersion = 77;\n\t\t\tproductRefGroup = {products_group} /* Products */;\n\t\t\tprojectDirPath = \"\";\n\t\t\tprojectRoot = \"\";\n\t\t\ttargets = (" + "".join(f"\n\t\t\t\t{target_ids[t[0]]} /* {t[0]} */," for t in targets) + "\n\t\t\t);\n\t\t}")

sections = {}
for identifier, comment, body in objects:
    isa = body.split("isa = ")[1].split(";")[0]
    sections.setdefault(isa, []).append((identifier, comment, body))

out = ["// !$*UTF8*$!", "{", "\tarchiveVersion = 1;", "\tclasses = {", "\t};", "\tobjectVersion = 77;", "\tobjects = {", ""]
for isa in sorted(sections):
    out.append(f"/* Begin {isa} section */")
    for identifier, comment, body in sorted(sections[isa]):
        label = f" /* {comment} */" if comment else ""
        out.append(f"\t\t{identifier}{label} = {body};")
    out.append(f"/* End {isa} section */")
    out.append("")
out += ["\t};", f"\trootObject = {project_id} /* Project object */;", "}", ""]

os.makedirs(PROJECT, exist_ok=True)
with open(os.path.join(PROJECT, "project.pbxproj"), "w") as f:
    f.write("\n".join(out))


def scheme(name, app, tests, core_tests):
    app_ref = f'''<BuildableReference BuildableIdentifier = "primary" BlueprintIdentifier = "{target_ids[app]}" BuildableName = "WirePath.app" BlueprintName = "{app}" ReferencedContainer = "container:WirePath.xcodeproj">
            </BuildableReference>'''
    testables = []
    for test in tests:
        testables.append(f'''         <TestableReference skipped = "NO">
            <BuildableReference BuildableIdentifier = "primary" BlueprintIdentifier = "{target_ids[test]}" BuildableName = "{test}.xctest" BlueprintName = "{test}" ReferencedContainer = "container:WirePath.xcodeproj">
            </BuildableReference>
         </TestableReference>''')
    for package, test in core_tests:
        testables.append(f'''         <TestableReference skipped = "NO">
            <BuildableReference BuildableIdentifier = "primary" BlueprintIdentifier = "{test}" BuildableName = "{test}" BlueprintName = "{test}" ReferencedContainer = "container:Packages/{package}">
            </BuildableReference>
         </TestableReference>''')
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion = "2700" version = "1.7">
   <BuildAction parallelizeBuildables = "YES" buildImplicitDependencies = "YES">
      <BuildActionEntries>
         <BuildActionEntry buildForTesting = "YES" buildForRunning = "YES" buildForProfiling = "YES" buildForArchiving = "YES" buildForAnalyzing = "YES">
            {app_ref}
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <TestAction buildConfiguration = "Debug" selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv = "YES">
      <Testables>
{chr(10).join(testables)}
      </Testables>
   </TestAction>
   <LaunchAction buildConfiguration = "Debug" selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB" launchStyle = "0" useCustomWorkingDirectory = "NO" ignoresPersistentStateOnLaunch = "NO" debugDocumentVersioning = "YES" debugServiceExtension = "internal" allowLocationSimulation = "YES">
      <BuildableProductRunnable runnableDebuggingMode = "0">
            {app_ref}
      </BuildableProductRunnable>
   </LaunchAction>
   <ProfileAction buildConfiguration = "Release" shouldUseLaunchSchemeArgsEnv = "YES" savedToolIdentifier = "" useCustomWorkingDirectory = "NO" debugDocumentVersioning = "YES">
      <BuildableProductRunnable runnableDebuggingMode = "0">
            {app_ref}
      </BuildableProductRunnable>
   </ProfileAction>
   <AnalyzeAction buildConfiguration = "Debug">
   </AnalyzeAction>
   <ArchiveAction buildConfiguration = "Release" revealArchiveInOrganizer = "YES">
   </ArchiveAction>
</Scheme>
'''


schemes = os.path.join(PROJECT, "xcshareddata", "xcschemes")
os.makedirs(schemes, exist_ok=True)
# Package tests run through each package's own "<Package>-Package" scheme (swift test / xcodebuild), not the
# app schemes: Xcode does not accept local-package test targets as members of a project scheme.
core_tests = []
with open(os.path.join(schemes, "WirePathMac.xcscheme"), "w") as f:
    f.write(scheme("WirePathMac", "WirePathMac", ["WirePathMacUITests"], core_tests))
with open(os.path.join(schemes, "WirePathiPad.xcscheme"), "w") as f:
    f.write(scheme("WirePathiPad", "WirePathiPad", ["WirePathiPadUITests"], core_tests))
print("wrote", PROJECT)
