import copy
import importlib.util
import json
from pathlib import Path
import shutil
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'skills/hhy-windows-storage/scripts/verify_migration.py'
spec = importlib.util.spec_from_file_location('verify_migration', MODULE)
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class MigrationVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.destination = self.root / 'destination'
        (self.source / 'empty').mkdir(parents=True)
        (self.source / 'nested').mkdir()
        (self.source / 'nested/data.bin').write_bytes(bytes(range(128)))
        (self.source / '中文.txt').write_text('verified data\n', encoding='utf-8')
        self.manifest = vm.snapshot(self.source)
        shutil.copytree(self.source, self.destination)

    def test_good_copy_and_source_unchanged(self):
        result = vm.verify(self.manifest, self.destination, check_source=True)
        self.assertTrue(result['passed'])
        self.assertTrue(result['source_check']['passed'])
        self.assertEqual((self.source / '中文.txt').read_text(encoding='utf-8'), 'verified data\n')

    def test_same_size_corruption_is_detected(self):
        (self.destination / 'nested/data.bin').write_bytes(bytes(reversed(range(128))))
        result = vm.verify(self.manifest, self.destination)
        self.assertFalse(result['passed'])
        self.assertEqual(result['destination_check']['changed_files'], ['nested/data.bin'])

    def test_missing_file(self):
        (self.destination / '中文.txt').unlink()
        self.assertFalse(vm.verify(self.manifest, self.destination)['passed'])

    def test_missing_empty_directory(self):
        (self.destination / 'empty').rmdir()
        result = vm.verify(self.manifest, self.destination)
        self.assertFalse(result['passed'])
        self.assertEqual(result['destination_check']['missing_directories'], ['empty'])

    def test_extras_require_explicit_allowance(self):
        (self.destination / 'extra.txt').write_text('extra', encoding='utf-8')
        self.assertFalse(vm.verify(self.manifest, self.destination)['passed'])
        result = vm.verify(self.manifest, self.destination, allow_extra=True)
        self.assertTrue(result['passed'])
        self.assertEqual(result['destination_check']['extra_files'], ['extra.txt'])

    def test_changed_source_blocks_pass_when_checked(self):
        (self.source / '中文.txt').write_text('changed source', encoding='utf-8')
        result = vm.verify(self.manifest, self.destination, check_source=True)
        self.assertFalse(result['passed'])
        self.assertTrue(result['destination_check']['passed'])

    def test_new_source_file_detected(self):
        (self.source / 'new.txt').write_text('new', encoding='utf-8')
        self.assertFalse(vm.verify(self.manifest, self.destination, check_source=True)['passed'])

    def test_incomplete_source_inventory_rejected(self):
        with patch.object(vm, 'stable_hash', side_effect=PermissionError('exclusive test lock')):
            incomplete = vm.snapshot(self.source)
        self.assertFalse(incomplete['complete'])
        self.assertTrue(incomplete['errors'])
        with self.assertRaises(ValueError):
            vm.verify(incomplete, self.destination)

    def test_manifest_path_traversal_rejected(self):
        for bad in ['../outside', '/absolute', 'C:/outside', 'nested/../escape', 'nested\\data.bin']:
            manifest = copy.deepcopy(self.manifest)
            manifest['files'][0]['path'] = bad
            with self.subTest(path=bad), self.assertRaises(ValueError):
                vm.verify(manifest, self.destination)

    def test_duplicate_manifest_paths_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['files'].append(copy.deepcopy(manifest['files'][0]))
        with self.assertRaises(ValueError):
            vm.verify(manifest, self.destination)

    def test_source_destination_overlap_rejected(self):
        with self.assertRaises(ValueError):
            vm.verify(self.manifest, self.source)
        with self.assertRaises(ValueError):
            vm.verify(self.manifest, self.source / 'empty')

    def test_output_does_not_overwrite_existing_file(self):
        output = self.root / 'report.json'
        output.write_text('keep original', encoding='utf-8')
        with self.assertRaises(FileExistsError):
            vm.write_new_json(output, self.manifest, [self.source])
        self.assertEqual(output.read_text(encoding='utf-8'), 'keep original')

    def test_output_cannot_contaminate_scanned_tree(self):
        with self.assertRaises(ValueError):
            vm.write_new_json(self.source / 'manifest.json', self.manifest, [self.source])
        self.assertFalse((self.source / 'manifest.json').exists())

    def test_cli_manifest_and_report_flow(self):
        import subprocess
        import sys
        inventory = self.root / 'inventory.json'
        result = subprocess.run([sys.executable, str(MODULE), 'snapshot', str(self.source), str(inventory)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / 'result.json'
        result = subprocess.run([sys.executable, str(MODULE), 'verify', str(inventory), str(self.destination), str(output), '--check-source'], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(output.read_text(encoding='utf-8'))['passed'])

    def make_directory_link(self, name, target):
        link = self.root / name
        self.assertTrue(link.resolve().is_relative_to(self.root.resolve()))
        self.assertTrue(target.resolve().is_relative_to(self.root.resolve()))
        if os.name == 'nt':
            result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.addCleanup(lambda: os.rmdir(link) if link.exists() else None)
        else:
            link.symlink_to(target, target_is_directory=True)
            self.addCleanup(lambda: link.unlink() if link.is_symlink() else None)
        return link

    def test_linked_root_is_rejected(self):
        link = self.make_directory_link('root-link', self.source)
        with self.assertRaises(ValueError):
            vm.snapshot(link)

    def test_nested_reparse_point_fails_without_following(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'protected.txt').write_text('keep protected content', encoding='utf-8')
        link = self.make_directory_link('nested-link', outside)
        moved_link = self.destination / 'linked'
        link.rename(moved_link)
        # Cleanup only the link itself; never traverse its target.
        self.addCleanup(lambda: os.rmdir(moved_link) if os.name == 'nt' and moved_link.exists()
                        else moved_link.unlink() if moved_link.is_symlink() else None)
        result = vm.verify(self.manifest, self.destination, allow_extra=True)
        self.assertFalse(result['passed'])
        self.assertTrue(result['destination_check']['scan_errors'])
        self.assertEqual((outside / 'protected.txt').read_text(encoding='utf-8'), 'keep protected content')


if __name__ == '__main__':
    unittest.main(verbosity=2)
