#!/usr/bin/env python3
"""Builds the replay harness against either the submitted code or the working tree.

  python build_harness.py baseline   # sources from git commit BASELINE_COMMIT (app v1.3.0)
  python build_harness.py current    # sources from the working tree
  python build_harness.py baseline_nowild   # v1.3.0 with only the rule regexes' end wildcards removed
  python build_harness.py baseline_nohex    # v1.3.0 with only its per-byte hex formatting replaced

Each build yields build/<name>/harness.jar (desktop JVM) and build/<name>/harness.dex (phone, ART).
The only transformation applied to production sources is the mechanical clock rewrite:
System.currentTimeMillis() -> EvalClock.now().
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVAL = ROOT / "evaluation"
BASELINE_COMMIT = "93d058f"
KT_DIR = "android/app/src/main/kotlin/com/example/packet_analyzer"
SOURCES = {
    "baseline": ["AnomalyDetector.kt", "SignatureDatabase.kt", "RuleEngine.kt", "PacketDissector.kt",
                 "PayloadAnalyzer.kt", "DomainTracker.kt", "AdaptiveThresholdManager.kt", "TrafficStatistics.kt"],
    "current": ["AnomalyDetector.kt", "SignatureDatabase.kt", "RuleEngine.kt", "PacketDissector.kt",
                "PayloadAnalyzer.kt", "DomainTracker.kt", "AdaptiveThresholdManager.kt", "TrafficStatistics.kt",
                "PacketRecord.kt", "PacketPipeline.kt", "PacketClock.kt", "FlowTable.kt", "AppContext.kt", "FlowDetectors.kt",
                "TlsFingerprint.kt"],
}
SOURCES["v151"] = SOURCES["current"]
SOURCES["baseline_nowild"] = SOURCES["baseline"]
SOURCES["baseline_nohex"] = SOURCES["baseline"]
# The same text as "%02x".format per byte, built from a digit table
HEX_LOOP = """val payloadHex = run {
            val digits = "0123456789abcdef"
            val n = minOf(payload.size, 666)
            val hex = StringBuilder(n * 3)
            for (i in 0 until n) {
                if (i > 0) hex.append(' ')
                val v = payload[i].toInt() and 0xFF
                hex.append(digits[v ushr 4]).append(digits[v and 0x0F])
            }
            hex.toString()
        }"""

HOME = pathlib.Path.home()
SDK = pathlib.Path(os.environ.get("ANDROID_HOME") or HOME / "AppData/Local/Android/Sdk")
ANDROID_JAR = SDK / "platforms/android-37/android.jar"
D8_JAR = SDK / "build-tools/37.0.0/lib/d8.jar"
CACHE = HOME / ".gradle/caches/modules-2/files-2.1"


def jar(group, artifact, version, required=True):
    hits = [p for p in (CACHE / group / artifact / version).rglob(f"{artifact}-{version}.jar")]
    if not hits:
        # Gradle prunes versions it no longer needs. The compiler's support jars tolerate a nearby
        # version, but the compiler itself and the stdlib must match, so a build fails below if not.
        hits = sorted((CACHE / group / artifact).rglob(f"{artifact}-*.jar"))
        hits = [p for p in hits if "sources" not in p.name]
    if not hits:
        if not required:
            return None
        sys.exit(f"missing {artifact} in the Gradle cache")
    return str(hits[-1])


KOTLIN = "2.2.21"
STDLIB = jar("org.jetbrains.kotlin", "kotlin-stdlib", KOTLIN)
COMPILER_CP = [
    jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", KOTLIN), STDLIB,
    jar("org.jetbrains.kotlin", "kotlin-script-runtime", KOTLIN),
    jar("org.jetbrains.kotlin", "kotlin-reflect", KOTLIN),
    jar("org.jetbrains.kotlin", "kotlin-daemon-embeddable", KOTLIN),
    jar("org.jetbrains.intellij.deps", "trove4j", "1.0.20200330", required=False),
    jar("org.jetbrains", "annotations", "13.0"),
    jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.10.2"),
]
COMPILER_CP = [c for c in COMPILER_CP if c]


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd)[:220])
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def production_sources(which, dest):
    dest.mkdir(parents=True, exist_ok=True)
    for name in SOURCES[which]:
        if which.startswith("baseline"):
            text = subprocess.check_output(["git", "-C", str(ROOT), "show", f"{BASELINE_COMMIT}:{KT_DIR}/{name}"]).decode("utf-8")
        else:
            text = (ROOT / KT_DIR / name).read_text(encoding="utf-8")
        text = text.replace("System.currentTimeMillis()", "EvalClock.now()")
        if which == "baseline_nowild" and name == "RuleEngine.kt":
            # Isolates one cause of the v1.3.0 rule cost. Its rules match with containsMatchIn, so
            # a wildcard at either end of a pattern changes the cost and never the verdict.
            text, leading = re.subn(r'Regex\("\.\*', 'Regex("', text)
            text, trailing = re.subn(r'\.\*"(?=[,)])', '"', text)
            print(f"removed {leading} leading and {trailing} trailing wildcards")
        if which == "baseline_nohex" and name == "PacketDissector.kt":
            # Isolates the formatting share of the v1.3.0 dissection cost
            unix = text.replace("\r\n", "\n")
            old = 'val payloadHex = payload.take(666).joinToString(" ") { byte ->\n            "%02x".format(byte)\n        }'
            if old not in unix:
                sys.exit("the v1.3.0 hex formatting code was not found")
            text = unix.replace(old, HEX_LOOP)
        (dest / name).write_text(text, encoding="utf-8")


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "current"
    out = EVAL / "build" / which
    shutil.rmtree(out, ignore_errors=True)
    src = out / "gen"
    production_sources(which, src)

    classes = out / "classes"
    classes.mkdir(parents=True)
    kt_files = [str(p) for p in src.glob("*.kt")]
    kt_files += [str(p) for p in (EVAL / "harness/src").rglob("*.kt")]
    kt_files += [str(p) for p in (EVAL / "harness/stubs").rglob("*.kt")]
    pipeline = "baseline" if which.startswith("baseline") else "current"
    kt_files += [str(p) for p in (EVAL / f"harness/pipeline_{pipeline}").rglob("*.kt")]
    run(["java", "-Xmx2g", "-cp", os.pathsep.join(COMPILER_CP), "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
         "-no-stdlib", "-no-reflect", "-nowarn", "-jvm-target", "17",
         "-cp", os.pathsep.join([STDLIB, str(ANDROID_JAR)]), "-d", classes] + kt_files)

    host_cls = out / "host_classes"
    host_cls.mkdir()
    javac = shutil.which("javac")
    if javac:
        run([javac, "-d", host_cls, EVAL / "harness/stubs/android/util/Log.java"])

    harness_jar = out / "harness.jar"
    shutil.make_archive(str(harness_jar.with_suffix("")), "zip", classes)
    (out / "harness.zip").replace(harness_jar)

    dex_dir = out / "dex"
    dex_dir.mkdir()
    run(["java", "-Xmx2g", "-cp", D8_JAR, "com.android.tools.r8.D8", "--release", "--min-api", "33",
         "--lib", ANDROID_JAR, "--output", dex_dir, harness_jar, STDLIB])
    shutil.copy(dex_dir / "classes.dex", out / "harness.dex")
    print("built", harness_jar, "and", out / "harness.dex")
    print("host run: java -cp", os.pathsep.join([str(harness_jar), str(host_cls), STDLIB]), "com.andronet.eval.ReplayMainKt ...")


if __name__ == "__main__":
    main()
