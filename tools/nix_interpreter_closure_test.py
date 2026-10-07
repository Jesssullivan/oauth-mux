"""Pure registration graph tests; no Nix or executable invocation."""
import unittest

from nix_interpreter_closure import CAPABILITIES, reachable, registrations, select


class InterpreterClosureTests(unittest.TestCase):
    def setUp(self):
        self.roots = ["/nix/store/" + character * 32 + "-" + name
                      for character, name in zip("abcdfg", ("python", "node", "bash", "libc", "compiler", "node-library"))]
        python, node, bash, libc, compiler, node_library = self.roots
        self.refs = {python: [python, libc], node: [node_library, libc], bash: [libc],
                     libc: [], compiler: [libc], node_library: [node]}
        self.native = {"packages": {name: {"out": root} for name, root in zip(("python", "node", "bash"), self.roots)}}
        self.inventory = {"files": ["closure/" + root.rsplit("/", 1)[1] + "/payload" for root in self.roots]}

    def registration(self):
        return "".join("\n".join([root, "sha256:" + "0" * 52, "10", "", str(len(self.refs[root])), *self.refs[root]]) + "\n"
                       for root in self.roots)

    def test_exact_python_and_node_closures_exclude_compiler(self):
        groups = select(self.native, self.roots, self.registration(), self.inventory)["groups"]
        self.assertEqual(set(groups["python"]["roots"]), {self.roots[i] for i in (0, 2, 3)})
        self.assertEqual(set(groups["node"]["roots"]), {self.roots[i] for i in (1, 2, 3, 5)})
        self.assertEqual(set(groups["bash"]["roots"]), {self.roots[i] for i in (2, 3)})
        for group in groups.values():
            self.assertNotIn(self.roots[4], group["roots"])
            self.assertEqual(set(registrations(group["registration"], group["roots"])), set(group["roots"]))

    def test_self_and_mutual_cycles_terminate_without_dropping_dependencies(self):
        records = registrations(self.registration(), self.roots)
        self.assertEqual(reachable(records, [self.roots[0]]), sorted([self.roots[0], self.roots[3]]))
        self.assertEqual(set(reachable(records, [self.roots[1]])), {self.roots[i] for i in (1, 3, 5)})

    def test_unknown_reference_duplicate_record_and_incomplete_graph_refuse(self):
        unknown = "/nix/store/" + "h" * 32 + "-unknown"
        self.refs[self.roots[0]].append(unknown)
        with self.assertRaises(ValueError):
            registrations(self.registration(), self.roots)
        self.refs[self.roots[0]].pop()
        with self.assertRaises(ValueError):
            registrations(self.registration() + self.registration(), self.roots)
        with self.assertRaises(ValueError):
            registrations(self.registration(), self.roots[:-1])

    def test_invalid_hash_range_and_count_refuse(self):
        for altered in (self.registration().replace("sha256:" + "0" * 52, "sha256:" + "z" * 52, 1),
                        self.registration().replace("\n10\n", "\n0\n", 1),
                        self.registration()[:-10]):
            with self.assertRaises(ValueError):
                registrations(altered, self.roots)

    def test_missing_inventoried_dependency_and_missing_seed_refuse(self):
        self.inventory["files"].pop(3)
        with self.assertRaises(ValueError):
            select(self.native, self.roots, self.registration(), self.inventory)
        with self.assertRaises(ValueError):
            reachable(registrations(self.registration(), self.roots), ["/nix/store/missing"])

    def test_regular_store_root_file_is_a_complete_dependency(self):
        singleton = "closure/" + self.roots[3].rsplit("/", 1)[1]
        self.inventory["files"][3] = singleton
        groups = select(self.native, self.roots, self.registration(), self.inventory)["groups"]
        for group in groups.values():
            self.assertIn(singleton, group["files"])

    def test_root_basename_prefix_collision_does_not_expand_subset(self):
        old_root = self.roots[4]
        collision = self.roots[3] + "-compiler"
        self.refs[collision] = self.refs.pop(old_root)
        self.roots[4] = collision
        collision_file = "closure/" + collision.rsplit("/", 1)[1] + "/payload"
        self.inventory["files"][4] = collision_file
        groups = select(self.native, self.roots, self.registration(), self.inventory)["groups"]
        for group in groups.values():
            self.assertNotIn(collision, group["roots"])
            self.assertNotIn(collision_file, group["files"])

    def test_finite_native_capabilities_keep_complete_reachable_files(self):
        root = self.roots[4]
        executable = root + "/bin/native-tool"
        alias = "closure/" + root.rsplit("/", 1)[1] + "/bin/native-tool"
        self.inventory["files"].append(alias)
        # Include a transitive mutual cycle as well as Bash's shared libc.
        self.refs[root].append(self.roots[1])
        resolved = {name: executable for name in CAPABILITIES}
        groups = select(self.native, self.roots, self.registration(), self.inventory, resolved)["groups"]
        for name in CAPABILITIES:
            expected_roots = {self.roots[i] for i in (1, 2, 3, 4, 5)}
            self.assertEqual(set(groups[name]["roots"]), expected_roots)
            expected_files = {file for file in self.inventory["files"]
                              if "/nix/store/" + file.split("/")[1] in expected_roots}
            self.assertEqual(set(groups[name]["files"]), expected_files)
            self.assertEqual(set(registrations(groups[name]["registration"], groups[name]["roots"])), expected_roots)
            self.assertNotIn(self.roots[0], groups[name]["roots"])
        self.assertEqual(set(select(self.native, self.roots, self.registration(), self.inventory, {})["groups"]),
                         {"python", "node", "bash"})

    def test_native_capability_map_refuses_unknown_unsafe_or_uninventoried(self):
        executable = self.roots[4] + "/bin/native-tool"
        alias = "closure/" + self.roots[4].rsplit("/", 1)[1] + "/bin/native-tool"
        self.inventory["files"].append(alias)
        for resolved in ({"compiler": executable}, [], {"moc": executable + "/../other"},
                         {"moc": executable.replace("/bin/", "//bin/")}, {"moc": "/usr/bin/moc"},
                         {"moc": self.roots[4] + "/bin/missing"}, {"moc": None}):
            with self.subTest(resolved=resolved), self.assertRaises(ValueError):
                select(self.native, self.roots, self.registration(), self.inventory, resolved)
        self.inventory["files"].pop(3)
        with self.assertRaises(ValueError):
            select(self.native, self.roots, self.registration(), self.inventory, {"moc": executable})


if __name__ == "__main__":
    unittest.main()
