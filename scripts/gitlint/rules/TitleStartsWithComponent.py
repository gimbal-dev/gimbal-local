# SPDX-License-Identifier: Apache-2.0

from gitlint.rules import LineRule, RuleViolation, CommitMessageTitle
import re


class TitleStartsWithComponent(LineRule):
    """A rule to enforce valid commit message title

    Valid title format:
    component1[, component2, componentN]: submodule: summary

    Title should have at least one component
    Components are separated by comma+space: ", "
    Components are validated to be in valid_components
    Components list is ended by a colon
    Submodules are not validated

    """

    # A rule MUST have a human friendly name
    name = "title-has-valid-component"

    # A rule MUST have a *unique* id.
    # We recommend starting with UL (for User-defined Line-rule)
    id = "UL1"

    # A line-rule MUST have a target (not required for CommitRules).
    target = CommitMessageTitle

    def validate(self, line, _commit):
        # Upstream Cloud Hypervisor's components, plus this fork's own. The
        # fork entries are not aspirational: each is measured in `git log`,
        # and `app` (37 commits) and `hvf` (12) are both advertised as
        # examples in CONTRIBUTING.md, which is how this list was found to be
        # wrong. Keep this in sync with the list in CONTRIBUTING.md.
        valid_components = (
            'api_client',
            'app',
            'arch',
            'block',
            'build',
            'ch-remote',
            'chm',
            'chore',
            'ci',
            'credproxy',
            'devices',
            'docs',
            'event_monitor',
            'fuzz',
            'github',
            'gitignore',
            'gitlint',
            'hvf',
            'hypervisor',
            'main',
            'misc',
            'nat',
            'net_util',
            'netget',
            'offload_daemon',
            'openapi',
            'option_parser',
            'pci',
            'performance-metrics',
            'rate_limiter',
            'README',
            'release',
            'resources',
            'scripts',
            'seccomp',
            'security',
            'serial_buffer',
            'test_data',
            'test_infra',
            'tests',
            'tpm',
            'tracer',
            'vhost_user_net',
            'virtio-devices',
            'vm-allocator',
            'vm-device',
            'vmm',
            'vm-migration',
            'vm-virtio')

        ptrn_title = re.compile(r'^(.+?):\s(.+)$')
        match = ptrn_title.match(line)

        if not match:
            self.log.debug("Invalid commit title {}", line)
            return [RuleViolation(self.id, "Commit title does not comply with "
                                  "rule: 'component: change summary'")]
        components = match.group(1)
        summary = match.group(2)
        self.log.debug(f"\nComponents: {components}\nSummary: {summary}")

        # Practice writes both "chm, app:" and "chm,app:", so the space is
        # optional here. Requiring it rejected commits that were otherwise
        # correct.
        ptrn_components = re.compile(r',\s*')
        components_list = re.split(ptrn_components, components)
        self.log.debug("components list: %s" % components_list)

        # A conventional-commits scope is allowed and ignored: dependabot
        # opens every bump as `build(deps): ...`, which is a correctly
        # scoped `build` commit that this rule used to reject outright.
        ptrn_scope = re.compile(r'\([^()]*\)$')

        for component in components_list:
            if re.sub(ptrn_scope, '', component) not in valid_components:
                return [RuleViolation(self.id,
                                      f"Invalid component: {component}, "
                                      "\nValid components are: {}".format(
                                          " ".join(valid_components)))]
