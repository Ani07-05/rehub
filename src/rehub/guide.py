"""Built-in help. Answers common questions without any model, and supplies the manual a model
may use when you choose to ask one."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Topic:
    title: str
    keywords: frozenset[str]
    answer: str


def _topic(title: str, words: str, answer: str) -> Topic:
    return Topic(title, frozenset(words.split()), answer)


TOPICS = [
    _topic(
        "What is rehub for?",
        "rehub for purpose product tool does overview about",
        "rehub answers one question: did anything change on my plant network? You give it a "
        "recording of normal traffic, later you give it a newer recording, and it shows new "
        "devices, risky commands such as a PLC stop or program download, and devices that "
        "went quiet. It only reads files and never sends anything to your network.",
    ),
    _topic(
        "What is a capture (pcap) file?",
        "pcap capture recording file packet packets format",
        "A pcap is a recording of network traffic, like a voice recorder for the network. It "
        "holds every message that crossed the wire during the recording. rehub reads it and "
        "does not change it.",
    ),
    _topic(
        "Where do I get a capture?",
        "get record recording mirror span port switch wireshark tcpdump take make obtain",
        "Ask whoever manages the network switch to copy traffic to a mirror (SPAN) port, plug "
        "a laptop into it, and record for 30 to 60 minutes with Wireshark or with "
        "`rehub capture --iface IFACE --seconds 3600 --out normal.pcap`. Recording only "
        "listens. Do not use scanners on a live control network. If you just want to try "
        "rehub, use the bundled samples.",
    ),
    _topic(
        "What is a normal snapshot?",
        "baseline normal snapshot freeze save approved known good",
        "A normal snapshot is the list of conversations you accept as fine: which devices "
        "talk to which, over what protocol, and which risky actions are expected. Once saved "
        "it can never be edited, so nobody can quietly change what normal means. To accept new "
        "behavior you save a new snapshot under a new name.",
    ),
    _topic(
        "What do the colors and lines mean?",
        "red amber dashed color colors line lines rung meaning legend orange cyan blue",
        "Gray is normal and stays quiet. Red means two devices talked that never did in your "
        "normal snapshot. Amber means a known pair did something new, such as a program "
        "download or a stop command. A dashed line means a conversation from your snapshot did "
        "not happen in this recording. Every line also has a text label.",
    ),
    _topic(
        "What does a new action mean?",
        "action actions stop download upload write mode engineering new risky command",
        "An action is something beyond ordinary data exchange. Program download or upload "
        "changes or copies the PLC logic. Stop halts the controller. Mode change switches "
        "run/stop modes. Parameter write sets values in the device. These can change or halt "
        "a process, so rehub highlights them when they are new.",
    ),
    _topic(
        "What is the tool upgrade check?",
        "doctor upgrade tool tools version check golden update sensors zeek suricata",
        "Your monitoring tools (Zeek, Suricata and others) change between versions, and a "
        "change can quietly alter what they report. The upgrade check replays built-in test "
        "recordings through every tool and compares the results with the saved expected "
        "output. If a new version behaves differently it names exactly what changed. Run it "
        "against a new image before you switch your sensors.",
    ),
    _topic(
        "Is it safe to use on a live plant?",
        "safe safety live plant production crash send packets scan active passive risk",
        "rehub only reads recordings. The analysis tools run in a container with no network "
        "at all. The one command that listens to a network, capture, only listens. Nothing "
        "in rehub scans devices or sends packets, because an active scan can crash a PLC.",
    ),
    _topic(
        "Where is my data stored?",
        "data stored store database db where local file folder location delete saved",
        "Everything is on this computer in {home}. The database is {home}/rehub.db (a single "
        "SQLite file). Uploaded captures are in {home}/uploads and tool output is in "
        "{home}/runs. Set the REHUB_HOME environment variable to move it. Delete the folder "
        "to remove everything, apart from saved normal snapshots which live in that same "
        "database.",
    ),
    _topic(
        "Does anything leave my computer?",
        "leave cloud upload privacy internet hosted share external third party sent go goes",
        "No capture data and no PLC code leave this computer. The only time text leaves is if "
        "you choose a hosted AI model, and then you see exactly what would be sent and must "
        "confirm. A local model such as Ollama keeps everything on this computer.",
    ),
    _topic(
        "What does the PLC code check do?",
        "plc code program upload logic review check st scl l5x structured text updated",
        "Upload the source of a PLC program (Structured Text or SCL text, or a Rockwell L5X "
        "export). rehub flags risky patterns such as passwords written in the code, a stop "
        "instruction, forced values, network calls and fixed addresses, with a plain reason "
        "for each. If you approved an earlier version, it also shows what changed: new risky "
        "lines, and changed numbers such as setpoints.",
    ),
    _topic(
        "Can it find CVEs or vulnerabilities in my PLC?",
        "cve cves vulnerability vulnerabilities vuln firmware exploit scan patch",
        "No. There is no standard database of vulnerabilities in PLC programs, and rehub does "
        "not test firmware. The code check is a review of patterns a person should look at, "
        "plus a comparison with an approved version. Treat it as a second pair of eyes, not "
        "a guarantee.",
    ),
    _topic(
        "What are detection rules (YARA)?",
        "yara rule rules detect detection malware triton signature draft",
        "A rule describes a pattern to look for in a file, for example a known malware "
        "string. You can ask a model to draft one from a description. rehub compiles it and "
        "tests it on your sample files, and labels it Validated only if it passes. Always "
        "review a model-written rule.",
    ),
    _topic(
        "Which protocols does it understand?",
        "protocol protocols s7 siemens modbus ethernet enip cip rockwell dnp3 opc bacnet support",
        "Version 0.1 understands Siemens S7comm, EtherNet/IP with CIP (Rockwell and others) "
        "and Modbus/TCP. Traffic in other protocols is still listed as a plain connection.",
    ),
    _topic(
        "What does the AI model do here?",
        "ai model ollama assistant llm gpt claude agent",
        "The assistant answers questions about using rehub from its built-in manual. It is "
        "optional. If you ask a model, a local one keeps everything on this computer and a "
        "hosted one only receives your question and the manual, after you confirm.",
    ),
]

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    words = set()
    for word in _WORD.findall(text.lower()):
        words.add(word)
        if word.endswith("s") and len(word) > 3:
            words.add(word[:-1])
    return words


@dataclass(frozen=True)
class Answer:
    found: bool
    title: str
    text: str


def ask(question: str, home: str = "~/.rehub") -> Answer:
    words = _tokens(question)
    scored = sorted(
        ((len(words & t.keywords), t) for t in TOPICS), key=lambda pair: pair[0], reverse=True
    )
    best_score, best = scored[0]
    if best_score == 0 or (len(scored) > 1 and best_score == scored[1][0] and best_score < 2):
        return Answer(False, "", "")
    return Answer(True, best.title, best.answer.replace("{home}", home))


def titles() -> list[str]:
    return [t.title for t in TOPICS]


def manual(home: str = "~/.rehub") -> str:
    return "\n\n".join(f"{t.title}\n{t.answer.replace('{home}', home)}" for t in TOPICS)


MODEL_SYSTEM = (
    "You are the help assistant inside rehub, a tool that reviews OT network recordings and PLC "
    "code. Answer in plain, short sentences for a plant engineer who does not know security "
    "jargon. Use only the manual below. If the manual does not cover the question, say so and "
    "do not invent features.\n\nMANUAL\n\n"
)


def model_system(home: str = "~/.rehub") -> str:
    return MODEL_SYSTEM + manual(home)
