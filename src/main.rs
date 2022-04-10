/*
	This file is part of keywi.

	keywi is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	keywi is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with keywi.  If not, see <https://www.gnu.org/licenses/>.
*/

#![cfg_attr(feature = "dox", feature(doc_cfg))]
#![allow(clippy::needless_doctest_main)]
#![doc(
	html_logo_url = "https://github.com/Dirout/keywi/raw/master/branding/logo-filled.svg",
	html_favicon_url = "https://github.com/Dirout/keywi/raw/master/branding/logo-filled.svg"
)]
#![feature(async_closure)]

mod lib;
use chrono::Utc;
use directories_next::ProjectDirs;
use directories_next::UserDirs;
use gio::prelude::*;
use glib::clone;
use glib::Cast;
use gtk::prelude::BoxExt;
use gtk::prelude::ButtonExt;
use gtk::prelude::EditableExt;
use gtk::prelude::EntryExt;
use gtk::prelude::GtkWindowExt;
use gtk::prelude::PopoverExt;
use gtk::prelude::StyleContextExt;
use gtk::prelude::ToggleButtonExt;
use gtk::prelude::WidgetExt;
use std::convert::TryFrom;
use std::fs::File;
use std::path::PathBuf;

#[macro_use]
extern crate lazy_static;

lazy_static! {
	/// The platform-specific directories intended for keywi's use
	static ref PROJECT_DIRECTORIES: ProjectDirs =
		ProjectDirs::from("com", "github.dirout", "keywi").unwrap();
	/// The platform-specific directory where keywi caches data
	static ref CACHE_DIR: &'static str = PROJECT_DIRECTORIES.cache_dir().to_str().unwrap();
	/// The platform-specific directory where keywi stores user data
	static ref DATA_DIR: &'static str = PROJECT_DIRECTORIES.data_dir().to_str().unwrap();
	/// The platform-specific directories containing user files
	static ref USER_DIRECTORIES: UserDirs = UserDirs::new().unwrap();
	/// The platform-specific directory where users store pictures
	static ref PICTURES_DIR: &'static str = USER_DIRECTORIES.picture_dir().unwrap().to_str().unwrap();
}

/// The current release version number of keywi
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// Create a dialog box showing information about keywi
///
/// # Arguments
///
/// * `application` - The application data representing keywi
fn new_about_dialog(application: &gtk::Application) {
	//let about_dialog_builder = gtk::AboutDialogBuilder::new();
	let about_dialog = gtk::AboutDialog::builder()
		.version(VERSION.unwrap())
		.program_name("keywi")
		.logo_icon_name("com.github.dirout.keywi")
		.title("About keywi")
		.application(application)
		.icon_name("com.github.dirout.keywi")
		.license_type(gtk::License::Agpl30)
		.copyright("Copyright © 2022 Emil Sayahi")
		.destroy_with_parent(true)
		.modal(true)
		.build();
	about_dialog.show();
}

/// The main function of keywi
fn main() {
	let application = gtk::Application::new(Some("com.github.dirout.keywi"), Default::default());

	application.connect_activate(clone!(@weak application => move |_| {
		new_window(&application);
	}));

	application.run();
}

/// Create a new functional & graphical browser window
///
/// # Arguments
///
/// * `application` - The application data representing keywi
fn new_window(application: &gtk::Application) -> libadwaita::TabView {
	// Options
	let verbose = true;
	let is_private = true;
	// let mut native = true;
	let initial_url = "about:blank";

	// Browser header
	// Navigation bar
	//let nav_entry_builder = gtk::EntryBuilder::new();
	let nav_entry = gtk::Entry::builder()
		.can_focus(true)
		.focusable(true)
		.focus_on_click(true)
		.editable(true)
		.margin_top(4)
		.margin_bottom(4)
		.hexpand(true)
		.truncate_multiline(true)
		.placeholder_text("Enter an address … ")
		.input_purpose(gtk::InputPurpose::Url)
		.build();

	// Back button
	//let back_button_builder = gtk::ButtonBuilder::new();
	let back_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("go-previous")
		.build();
	back_button.style_context().add_class("linked");

	// Forward button
	//let forward_button_builder = gtk::ButtonBuilder::new();
	let forward_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("go-next")
		.build();
	forward_button.style_context().add_class("linked");

	// All navigation buttons
	//let navigation_buttons_builder = gtk::BoxBuilder::new();
	let navigation_buttons = gtk::Box::builder().homogeneous(true).build();
	navigation_buttons.append(&back_button);
	navigation_buttons.append(&forward_button);
	navigation_buttons.style_context().add_class("linked");

	// Add Tab button
	//let add_tab_builder = gtk::ButtonBuilder::new();
	let add_tab = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.margin_start(4)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("list-add")
		.build();

	// Refresh button
	//let refresh_button_builder = gtk::ButtonBuilder::new();
	let refresh_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_start(4)
		.margin_end(8)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("view-refresh")
		.build();

	// Left header buttons
	//let left_header_buttons_builder = gtk::BoxBuilder::new();
	let left_header_buttons = gtk::Box::builder().margin_end(4).build();
	left_header_buttons.append(&navigation_buttons);
	left_header_buttons.append(&add_tab);
	left_header_buttons.append(&refresh_button);

	// Downloads button
	//let downloads_button_builder = gtk::ButtonBuilder::new();
	let downloads_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_start(4)
		.margin_bottom(4)
		.icon_name("emblem-downloads")
		.build();

	// Find button
	//let find_button_builder = gtk::ButtonBuilder::new();
	let find_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_start(4)
		.margin_bottom(4)
		.icon_name("edit-find")
		.build();

	// IPFS menu button
	let ipfs_button = gtk::ToggleButton::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_start(4)
		.margin_bottom(4)
		.icon_name("emblem-shared")
		.build();

	// Onion routing button
	let tor_button = gtk::ToggleButton::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.hexpand(false)
		.vexpand(false)
		.overflow(gtk::Overflow::Hidden)
		.margin_start(4)
		.margin_bottom(4)
		.icon_name("security-medium")
		.build();

	// Menu button
	//let menu_button_builder = gtk::ButtonBuilder::new();
	let menu_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_start(4)
		.margin_bottom(4)
		.icon_name("document-properties")
		.build();

	// Right header buttons
	//let right_header_buttons_builder = gtk::BoxBuilder::new();
	let right_header_buttons = gtk::Box::builder()
		.margin_start(4)
		.spacing(2)
		.homogeneous(true)
		.build();
	right_header_buttons.append(&downloads_button);
	right_header_buttons.append(&find_button);
	right_header_buttons.append(&ipfs_button);
	right_header_buttons.append(&tor_button);
	right_header_buttons.append(&menu_button);

	// HeaderBar
	//let headerbar_builder = gtk::HeaderBarBuilder::new();
	let headerbar = gtk::HeaderBar::builder()
		.can_focus(true)
		.show_title_buttons(true)
		.title_widget(&nav_entry)
		.build();
	headerbar.pack_start(&left_header_buttons);
	headerbar.pack_end(&right_header_buttons);
	// End of browser header

	// Zoom out button
	//let zoomout_button_builder = gtk::ButtonBuilder::new();
	let zoomout_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("zoom-out")
		.build();
	zoomout_button.style_context().add_class("linked");

	// Zoom in button
	//let zoomin_button_builder = gtk::ButtonBuilder::new();
	let zoomin_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("zoom-in")
		.build();
	zoomin_button.style_context().add_class("linked");

	// Both zoom buttons
	//let zoom_buttons_builder = gtk::BoxBuilder::new();
	let zoom_buttons = gtk::Box::builder().homogeneous(true).build();
	zoom_buttons.append(&zoomout_button);
	zoom_buttons.append(&zoomin_button);
	zoom_buttons.style_context().add_class("linked");

	// Zoom reset button
	//let zoomreset_button_builder = gtk::ButtonBuilder::new();
	let zoomreset_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("zoom-original")
		.build();

	// Fullscreen button
	//let fullscreen_button_builder = gtk::ButtonBuilder::new();
	let fullscreen_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("video-display")
		.build();

	// Screenshot button
	//let screenshot_button_builder = gtk::ButtonBuilder::new();
	let screenshot_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("camera-photo")
		.build();

	// New Window button
	//let new_window_button_builder = gtk::ButtonBuilder::new();
	let new_window_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("window-new")
		.build();

	// History button
	//let history_button_builder = gtk::ButtonBuilder::new();
	let history_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("document-open-recent")
		.build();

	// Settings button
	//let settings_button_builder = gtk::ButtonBuilder::new();
	let settings_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("preferences-system")
		.build();

	// About button
	//let about_button_builder = gtk::ButtonBuilder::new();
	let about_button = gtk::Button::builder()
		.can_focus(true)
		.receives_default(true)
		.halign(gtk::Align::Start)
		.margin_top(4)
		.margin_bottom(4)
		.icon_name("help-about")
		.build();

	// Menu popover
	//let menu_box_builder = gtk::BoxBuilder::new();
	let menu_box = gtk::Box::builder()
		.margin_start(4)
		.margin_end(4)
		.margin_top(4)
		.margin_bottom(4)
		.spacing(8)
		.build();
	menu_box.append(&zoom_buttons);
	menu_box.append(&zoomreset_button);
	menu_box.append(&fullscreen_button);
	menu_box.append(&screenshot_button);
	menu_box.append(&new_window_button);
	menu_box.append(&history_button);
	menu_box.append(&settings_button);
	menu_box.append(&about_button);

	//let menu_builder = gtk::PopoverBuilder::new();
	let menu = gtk::Popover::builder().child(&menu_box).build();
	menu.set_parent(&menu_button);
	// End of menu popover

	// Tabs
	//let tab_view_builder = libadwaita::TabViewBuilder::new();
	let tab_view = libadwaita::TabView::builder().vexpand(true).build();

	//let tabs_builder = libadwaita::TabBarBuilder::new();
	let tabs = libadwaita::TabBar::builder()
		.autohide(true)
		.expand_tabs(true)
		.view(&tab_view)
		.build();

	if tab_view.n_pages() == 0 {
		create_initial_tab(
			&tabs,
			initial_url.to_owned(),
			verbose,
			is_private,
			&ipfs_button,
		)
	}
	// End of Tabs

	// Window
	//let main_box_builder = gtk::BoxBuilder::new();
	let main_box = gtk::Box::builder()
		.orientation(gtk::Orientation::Vertical)
		.vexpand(true)
		.build();
	main_box.append(&tabs);
	main_box.append(&tab_view);

	//let window_builder = gtk::ApplicationWindowBuilder::new();
	let window = gtk::ApplicationWindow::builder()
		.application(application)
		.can_focus(true)
		.title("keywi")
		.icon_name("com.github.dirout.keywi")
		.build();
	window.set_titlebar(Some(&headerbar));
	window.set_child(Some(&main_box));
	// End of Window

	// Signals
	// Add Tab button clicked
	add_tab.connect_clicked(clone!(@weak tabs, @weak ipfs_button => move |_| {
		new_tab_page(&tabs, verbose, is_private, &ipfs_button);
	}));

	// Back button clicked
	back_button.connect_clicked(clone!(@weak tabs, @weak nav_entry => move |_| {
		let web_view = get_view(&tabs);
		web_view.go_back()
	}));

	// Forward button clicked
	forward_button.connect_clicked(clone!(@weak tabs, @weak nav_entry => move |_| {
		let web_view = get_view(&tabs);
		web_view.go_forward()
	}));

	// Refresh button clicked
	refresh_button.connect_clicked(clone!(@weak tabs, @weak nav_entry => move |_| {
		let web_view = get_view(&tabs);
		web_view.reload_bypass_cache()
	}));

	// Selected tab changed
	tab_view.connect_selected_page_notify(
        clone!(@weak nav_entry, @weak tabs, @weak window => move |_| {
            let web_view = get_view(&tabs);
            update_nav_bar(&nav_entry, &web_view);
            window.set_title(Some(&web_view.title().unwrap_or_else(|| glib::GString::from("keywi")).to_string()));
        }),
    );

	// User hit return key in navbar, prompting navigation
	nav_entry.connect_activate(
		clone!(@weak tabs, @weak nav_entry, @weak window => move |_| {
			let web_view = get_view(&tabs);
			connect(&nav_entry, &web_view);
		}),
	);

	// Menu button clicked
	menu_button.connect_clicked(clone!(@weak menu => move |_| {
		menu.popup();
	}));

	// // IPFS button clicked
	// ipfs_button.connect_toggled(clone!(@weak ipfs_button, @weak tabs => move |_| {
	//     let web_view = get_view(&tabs);
	//     let web_context = web_view.context().unwrap();
	//     let mut native;
	//     if (ipfs_button.is_active()) {
	//         native = false;
	//     } else {
	//         native = true;
	//     }
	//     match native {
	//         true => {
	//             web_context.register_uri_scheme("ipfs", move |request| {
	//                 handle_ipfs_request_natively(request)
	//             });
	//         }
	//         false => {
	//             web_context.register_uri_scheme("ipfs", move |request| {
	//                 handle_ipfs_request_using_api(request)
	//             });
	//         }
	//     };
	// }));

	// Zoom-in button clicked
	zoomin_button.connect_clicked(clone!(@weak tabs, @weak nav_entry => move |_| {
		let web_view = get_view(&tabs);
		let current_zoom_level = web_view.zoom_level();
		web_view.set_zoom_level(current_zoom_level + 0.1);
	}));

	// Zoom-out button clicked
	zoomout_button.connect_clicked(clone!(@weak tabs, @weak nav_entry => move |_| {
		let web_view = get_view(&tabs);
		let current_zoom_level = web_view.zoom_level();
		web_view.set_zoom_level(current_zoom_level - 0.1);
	}));

	// Reset Zoom button clicked
	zoomreset_button.connect_clicked(clone!(@weak tabs, @weak nav_entry => move |_| {
		let web_view = get_view(&tabs);
		web_view.set_zoom_level(1.0);
	}));

	// Enter Fullscreen button clicked
	fullscreen_button.connect_clicked(
        clone!(@weak tabs, @weak nav_entry => move |_| {
            let web_view = get_view(&tabs);
            web_view.run_javascript("document.documentElement.webkitRequestFullscreen();", gio::Cancellable::NONE, move |_| {
            })
        }),
    );

	// Screenshot button clicked
	screenshot_button.connect_clicked(
        clone!(@weak tabs, @weak nav_entry => move |_| {
            let web_view = get_view(&tabs);
            web_view.snapshot(webkit2gtk::SnapshotRegion::FullDocument, webkit2gtk::SnapshotOptions::all(), gio::Cancellable::NONE, move |snapshot| {
                let snapshot_surface = cairo::ImageSurface::try_from(snapshot.unwrap()).unwrap();
                let mut writer = File::create(format!("{}/{}.png", PICTURES_DIR.to_owned(), Utc::now())).unwrap();
                snapshot_surface.write_to_png(&mut writer).unwrap();
            });
        }),
    );

	// New Window button clicked
	new_window_button.connect_clicked(
		clone!(@weak tabs, @weak nav_entry, @weak window => move |_| {
			new_window_four(&window.application().unwrap());
		}),
	);

	// About button clicked
	about_button.connect_clicked(
		clone!(@weak tabs, @weak nav_entry, @weak window => move |_| {
			new_about_dialog(&window.application().unwrap())
		}),
	);

	// Tab dragged off to create new browser window
	tab_view.connect_create_window(create_window_from_drag);
	// End of signals

	window.show();
	tab_view
}

/// Create new browser window when a tab is dragged off
///
/// # Arguments
///
/// * `tab_view` - The AdwTabView object containing each tab's WebView
fn create_window_from_drag(
	tab_view: &libadwaita::TabView,
) -> std::option::Option<libadwaita::TabView> {
	let window: gtk::ApplicationWindow = tab_view
		.parent()
		.unwrap()
		.parent()
		.unwrap()
		.downcast()
		.unwrap();
	let application = window.application().unwrap();
	let new_window = new_window_four(&application);
	Some(new_window)
}
