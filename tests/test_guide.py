import pytest

from rehub import guide


@pytest.mark.parametrize(
    ("question", "title"),
    [
        ("what is a pcap?", "What is a capture (pcap) file?"),
        ("where do I get a capture from the switch", "Where do I get a capture?"),
        ("where is the database stored", "Where is my data stored?"),
        ("is this safe on a live plant", "Is it safe to use on a live plant?"),
        ("can it find CVEs in my firmware", "Can it find CVEs or vulnerabilities in my PLC?"),
        ("what does the red line mean", "What do the colors and lines mean?"),
        ("what is the baseline", "What is a normal snapshot?"),
        ("does my data go to the cloud", "Does anything leave my computer?"),
        (
            "which protocols do you support, modbus or siemens",
            "Which protocols does it understand?",
        ),
    ],
)
def test_common_questions_are_answered(question: str, title: str) -> None:
    answer = guide.ask(question)
    assert answer.found
    assert answer.title == title


def test_unknown_question_is_not_guessed() -> None:
    assert not guide.ask("how tall is the eiffel tower").found
    assert not guide.ask("").found


def test_data_location_is_filled_in() -> None:
    answer = guide.ask("where is my database stored", "/home/me/.rehub")
    assert "/home/me/.rehub/rehub.db" in answer.text
    assert "{home}" not in answer.text


def test_every_topic_has_distinct_title_and_answer() -> None:
    titles = guide.titles()
    assert len(set(titles)) == len(titles)
    assert all(t.answer.strip() for t in guide.TOPICS)


def test_model_prompt_contains_manual_and_guardrail() -> None:
    system = guide.model_system("/x")
    assert "do not invent features" in system
    assert "/x/rehub.db" in system


def test_no_em_dash_in_help_text() -> None:
    assert "—" not in guide.manual()
