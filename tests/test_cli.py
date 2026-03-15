"""Tests for vita49_redteam.cli — CLI harness smoke tests."""

from click.testing import CliRunner

from vita49_redteam.cli import cli


class TestCLICraft:
    def test_craft_default(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["craft", "--hex-dump"])
        assert result.exit_code == 0
        assert "Crafted 1 packet" in result.output

    def test_craft_multiple(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["craft", "--count", "5", "--hex-dump"])
        assert result.exit_code == 0
        assert "Crafted 5 packet" in result.output

    def test_craft_with_payload(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "craft", "--payload-size", "128", "--hex-dump",
        ])
        assert result.exit_code == 0

    def test_craft_if_context(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "craft", "--type", "if_context", "--hex-dump",
        ])
        assert result.exit_code == 0

    def test_craft_with_timestamps(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "craft", "--tsi", "utc", "--tsf", "realtime",
            "--integer-ts", "1700000000", "--hex-dump",
        ])
        assert result.exit_code == 0

    def test_craft_to_pcap(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "test.pcap")
        result = runner.invoke(cli, ["craft", "--output", out])
        assert result.exit_code == 0
        assert "Written to" in result.output

    def test_craft_with_class_id(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "craft", "--class-id", "0012A2:ABCD:1234", "--hex-dump",
        ])
        assert result.exit_code == 0

    def test_craft_with_trailer(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "craft", "--trailer", "0xC0040000", "--hex-dump",
        ])
        assert result.exit_code == 0


class TestCLIReport:
    def test_report_on_crafted_pcap(self, tmp_path):
        """Craft packets to PCAP, then run report on them."""
        runner = CliRunner()
        pcap = str(tmp_path / "report_test.pcap")

        # Craft
        result = runner.invoke(cli, ["craft", "--count", "10", "--output", pcap])
        assert result.exit_code == 0

        # Report
        result = runner.invoke(cli, ["report", "--input", pcap])
        assert result.exit_code == 0
        assert "VITA 49 PCAP Report" in result.output
        assert "Stream IDs" in result.output


class TestCLIHelp:
    def test_root_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "craft" in result.output
        assert "send" in result.output
        assert "replay" in result.output
        assert "sniff" in result.output

    def test_craft_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["craft", "--help"])
        assert result.exit_code == 0
        assert "--stream-id" in result.output
