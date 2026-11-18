# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import textwrap
from pathlib import Path

import pytest

import capa.rules
import capa.loader
import capa.features.insn
import capa.render.verbose
import capa.features.common
import capa.features.freeze as frz
import capa.render.vverbose
import capa.capabilities.common
import capa.render.result_document as rdoc
from capa.features.address import NO_ADDRESS, ThreadAddress, ProcessAddress, DynamicCallAddress
from capa.features.extractors.null import (
    CallFeatures,
    ThreadFeatures,
    ProcessFeatures,
    NullDynamicFeatureExtractor,
)
from capa.features.extractors.base_extractor import SampleHashes

DUMMY_SAMPLE_HASHES = SampleHashes.from_bytes(b"")


PROCESS_RULE = textwrap.dedent("""
    rule:
        meta:
            name: process rule
            authors:
              - tester
            scopes:
                static: unsupported
                dynamic: process
        features:
            - string: "process-level"
""")

THREAD_RULE = textwrap.dedent("""
    rule:
        meta:
            name: thread rule
            authors:
              - tester
            scopes:
                static: unsupported
                dynamic: thread
        features:
            - string: "thread-level"
""")

CALL_RULE = textwrap.dedent("""
    rule:
        meta:
            name: call rule
            authors:
              - tester
            scopes:
                static: unsupported
                dynamic: call
        features:
            - api: CreateFileW
""")


def _ruleset(*yaml_docs: str) -> capa.rules.RuleSet:
    return capa.rules.RuleSet([capa.rules.Rule.from_yaml(doc) for doc in yaml_docs])


def _extractor(processes: dict[ProcessAddress, ProcessFeatures]) -> NullDynamicFeatureExtractor:
    return NullDynamicFeatureExtractor(
        base_address=NO_ADDRESS,
        sample_hashes=DUMMY_SAMPLE_HASHES,
        global_features=[],
        file_features=[],
        processes=processes,
    )


def _compute_layout(ruleset: capa.rules.RuleSet, extractor: NullDynamicFeatureExtractor):
    capabilities = capa.capabilities.common.find_capabilities(ruleset, extractor, disable_progress=True)
    layout = capa.loader.compute_dynamic_layout(ruleset, extractor, capabilities.matches)
    return capabilities, layout


def test_layout_includes_process_with_only_process_scope_matches():
    # regression: process-scope matches with no call-level matches
    # used to produce an empty layout and crash the verbose renderers.
    p = ProcessAddress(pid=3052)
    t = ThreadAddress(process=p, tid=3064)
    extractor = _extractor({
        p: ProcessFeatures(
            name="sample.exe",
            features=[(p, capa.features.common.String("process-level"))],
            threads={t: ThreadFeatures(features=[], calls={})},
        )
    })

    _, layout = _compute_layout(_ruleset(PROCESS_RULE), extractor)

    assert len(layout.processes) == 1
    proc = layout.processes[0]
    assert proc.address == frz.Address.from_capa(p)
    assert proc.name == "sample.exe"
    # no threads were referenced, so none should be present
    assert proc.matched_threads == ()


def test_layout_includes_thread_for_thread_scope_match_without_call_matches():
    p = ProcessAddress(pid=3052)
    t = ThreadAddress(process=p, tid=3064)
    # a call exists in the trace but matches nothing
    c = DynamicCallAddress(thread=t, id=1)
    extractor = _extractor({
        p: ProcessFeatures(
            name="sample.exe",
            features=[],
            threads={
                t: ThreadFeatures(
                    features=[(t, capa.features.common.String("thread-level"))],
                    calls={c: CallFeatures(name="kernel32.CreateFileW()", features=[])},
                )
            },
        )
    })

    _, layout = _compute_layout(_ruleset(THREAD_RULE), extractor)

    assert len(layout.processes) == 1
    proc = layout.processes[0]
    assert proc.name == "sample.exe"
    assert len(proc.matched_threads) == 1
    thread = proc.matched_threads[0]
    assert thread.address == frz.Address.from_capa(t)
    # the unreferenced call must not be pulled into the layout
    assert thread.matched_calls == ()


def test_layout_includes_call_thread_process_for_call_scope_matches():
    p = ProcessAddress(pid=3052)
    t = ThreadAddress(process=p, tid=3064)
    c = DynamicCallAddress(thread=t, id=1)
    extractor = _extractor({
        p: ProcessFeatures(
            name="sample.exe",
            features=[],
            threads={
                t: ThreadFeatures(
                    features=[],
                    calls={
                        c: CallFeatures(
                            name="kernel32.CreateFileW(hFile=...)",
                            features=[(c, capa.features.insn.API("CreateFileW"))],
                        )
                    },
                )
            },
        )
    })

    _, layout = _compute_layout(_ruleset(CALL_RULE), extractor)

    assert len(layout.processes) == 1
    proc = layout.processes[0]
    assert proc.name == "sample.exe"
    assert len(proc.matched_threads) == 1
    calls = proc.matched_threads[0].matched_calls
    assert len(calls) == 1
    assert calls[0].address == frz.Address.from_capa(c)
    assert calls[0].name == "kernel32.CreateFileW(hFile=...)"


def test_layout_excludes_unreferenced_processes_threads_and_calls():
    p = ProcessAddress(pid=3052)
    t_matched = ThreadAddress(process=p, tid=3064)
    t_quiet = ThreadAddress(process=p, tid=3065)
    c_matched = DynamicCallAddress(thread=t_matched, id=1)
    c_quiet = DynamicCallAddress(thread=t_matched, id=2)

    p_other = ProcessAddress(pid=9999)
    t_other = ThreadAddress(process=p_other, tid=4000)

    extractor = _extractor({
        p: ProcessFeatures(
            name="sample.exe",
            features=[],
            threads={
                t_matched: ThreadFeatures(
                    features=[(t_matched, capa.features.common.String("thread-level"))],
                    calls={
                        c_matched: CallFeatures(
                            name="kernel32.CreateFileW()",
                            features=[(c_matched, capa.features.insn.API("CreateFileW"))],
                        ),
                        # present in the trace but nothing matches at it
                        c_quiet: CallFeatures(name="kernel32.CloseHandle()", features=[]),
                    },
                ),
                # thread without any match
                t_quiet: ThreadFeatures(
                    features=[],
                    calls={DynamicCallAddress(thread=t_quiet, id=3): CallFeatures(name="x()", features=[])},
                ),
            },
        ),
        # whole process without any match
        p_other: ProcessFeatures(
            name="unreferenced.exe",
            features=[],
            threads={t_other: ThreadFeatures(features=[], calls={})},
        ),
    })

    _, layout = _compute_layout(_ruleset(THREAD_RULE, CALL_RULE), extractor)

    assert [proc.address.to_capa() for proc in layout.processes] == [p]
    proc = layout.processes[0]
    assert [thread.address.to_capa() for thread in proc.matched_threads] == [t_matched]
    # c_quiet is in the same thread but wasn't referenced, so it stays out
    assert [call.address.to_capa() for call in proc.matched_threads[0].matched_calls] == [c_matched]


# ---------------------------------------------------------------------------
# graceful degradation when the layout is missing entries
# (e.g. historical result documents whose layout.processes is empty)
# ---------------------------------------------------------------------------


def _dynamic_addresses():
    p = ProcessAddress(pid=3052)
    t = ThreadAddress(process=p, tid=3064)
    c = DynamicCallAddress(thread=t, id=7)
    return frz.Address.from_capa(p), frz.Address.from_capa(t), frz.Address.from_capa(c)


def test_renderers_degrade_with_empty_layout():
    empty_layout = rdoc.DynamicLayout(processes=())
    p_addr, t_addr, c_addr = _dynamic_addresses()

    assert capa.render.verbose.render_process(empty_layout, p_addr) == "process{pid:3052}"
    assert capa.render.verbose.render_thread(empty_layout, t_addr) == "process{pid:3052,tid:3064}"
    assert capa.render.verbose.render_call(empty_layout, c_addr) == "process{pid:3052,tid:3064,call:7}"
    assert capa.render.verbose.render_short_call(empty_layout, c_addr) == "call:7"
    assert capa.render.verbose.render_span_of_calls(empty_layout, [c_addr]) == "process{pid:3052,tid:3064,call:7}"
    assert (
        capa.render.verbose.render_span_of_calls(empty_layout, [c_addr, c_addr])
        == "process{pid:3052,tid:3064,calls:{7,7}}"
    )


def test_render_call_degrades_when_only_call_entry_is_missing():
    p_addr, t_addr, c_addr = _dynamic_addresses()
    # process and thread are known, but the call is not listed in the layout
    partial_layout = rdoc.DynamicLayout(
        processes=(
            rdoc.ProcessLayout(
                address=p_addr,
                name="sample.exe",
                matched_threads=(rdoc.ThreadLayout(address=t_addr, matched_calls=()),),
            ),
        )
    )

    assert capa.render.verbose.render_call(partial_layout, c_addr) == "sample.exe{pid:3052,tid:3064,call:7}"
    assert capa.render.verbose.render_short_call(partial_layout, c_addr) == "call:7"


def test_full_verbose_renderers_return_with_empty_layout():
    # end-to-end: build a real result document then strip the layout,
    # like rendering an older report whose layout.processes is an empty array.
    p = ProcessAddress(pid=3052)
    t = ThreadAddress(process=p, tid=3064)
    extractor = _extractor({
        p: ProcessFeatures(
            name="sample.exe",
            features=[(p, capa.features.common.String("process-level"))],
            threads={
                t: ThreadFeatures(
                    features=[(t, capa.features.common.String("thread-level"))],
                    calls={},
                )
            },
        )
    })
    ruleset = _ruleset(PROCESS_RULE, THREAD_RULE)
    capabilities, layout = _compute_layout(ruleset, extractor)

    meta = capa.loader.collect_metadata(
        argv=[],
        input_path=Path(__file__),
        input_format="auto",
        rules_path=[],
        extractor=extractor,
        capabilities=capabilities,
    )
    meta.analysis.layout = layout
    doc = rdoc.ResultDocument.from_capa(meta, ruleset, capabilities.matches)
    doc.meta.analysis.layout = rdoc.DynamicLayout(processes=())

    verbose = capa.render.verbose.render_verbose(doc)
    assert "process{pid:3052}" in verbose
    assert "process{pid:3052,tid:3064}" in verbose

    vverbose = capa.render.vverbose.render_vverbose(doc)
    assert "process{pid:3052}" in vverbose
    assert "process{pid:3052,tid:3064}" in vverbose


def test_renderers_use_names_when_layout_is_complete():
    p = ProcessAddress(pid=3052)
    t = ThreadAddress(process=p, tid=3064)
    c = DynamicCallAddress(thread=t, id=1)
    extractor = _extractor({
        p: ProcessFeatures(
            name="sample.exe",
            features=[],
            threads={
                t: ThreadFeatures(
                    features=[],
                    calls={
                        c: CallFeatures(
                            name="kernel32.CreateFileW()",
                            features=[(c, capa.features.insn.API("CreateFileW"))],
                        )
                    },
                )
            },
        )
    })
    _, layout = _compute_layout(_ruleset(CALL_RULE), extractor)
    p_addr, t_addr, c_addr = (
        frz.Address.from_capa(p),
        frz.Address.from_capa(t),
        frz.Address.from_capa(c),
    )

    assert capa.render.verbose.render_process(layout, p_addr) == "sample.exe{pid:3052}"
    assert capa.render.verbose.render_thread(layout, t_addr) == "sample.exe{pid:3052,tid:3064}"
    rendered_call = capa.render.verbose.render_call(layout, c_addr)
    assert rendered_call.startswith("sample.exe{pid:3052,tid:3064,call:1}\nkernel32.CreateFileW(")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
