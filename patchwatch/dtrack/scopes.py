# SPDX-License-Identifier: Apache-2.0
"""Mirror standard CI policies into a separate scope without production notifications."""
import copy

MR_TAG = "scan-purpose:mr-feedback"
BRANCH_TAG = "scan-purpose:branch"
SCOPED_TAGS = frozenset({MR_TAG, BRANCH_TAG})


def is_scoped(project):
    """Versions owned by merge requests or feature branches; never releases or baselines."""
    return any((t.get("name") if isinstance(t, dict) else t) in SCOPED_TAGS for t in project.get("tags") or [])


def definitions(policies):
    """Copies of the CI policies for merge-request and branch versions, so that feedback scans never raise production notifications."""
    result = []
    for policy in policies:
        if not {"managed-by:patchwatch", "source:gitlab-ci"}.intersection(policy["scopeTags"]):
            continue
        derived = copy.deepcopy(policy)
        derived["name"] = "Patchwatch MR " + policy["name"].removeprefix("Patchwatch ")
        derived["scopeTags"] = [MR_TAG, BRANCH_TAG]
        result.append(derived)
    return result
