import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_zh.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'localization/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
    : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations? of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations);
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
        delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('zh'),
  ];

  /// The title of the application
  ///
  /// In en, this message translates to:
  /// **'Personal AI Assistant'**
  String get appTitle;

  /// Settings page title
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get settings;

  /// Language setting label
  ///
  /// In en, this message translates to:
  /// **'Language'**
  String get language;

  /// Option to follow system language
  ///
  /// In en, this message translates to:
  /// **'Follow System'**
  String get languageFollowSystem;

  /// English language option
  ///
  /// In en, this message translates to:
  /// **'English'**
  String get languageEnglish;

  /// Chinese language option
  ///
  /// In en, this message translates to:
  /// **'Chinese'**
  String get languageChinese;

  /// App preferences section title
  ///
  /// In en, this message translates to:
  /// **'App Preferences'**
  String get appPreferences;

  /// About section title
  ///
  /// In en, this message translates to:
  /// **'About'**
  String get about;

  /// App version label
  ///
  /// In en, this message translates to:
  /// **'Version'**
  String get version;

  /// API documentation link label
  ///
  /// In en, this message translates to:
  /// **'API Documentation'**
  String get apiDocs;

  /// Profile page title
  ///
  /// In en, this message translates to:
  /// **'Profile'**
  String get profile;

  /// Preferences section title
  ///
  /// In en, this message translates to:
  /// **'Preferences'**
  String get preferences;

  /// Logout button label
  ///
  /// In en, this message translates to:
  /// **'Logout'**
  String get logout;

  /// Logout confirmation message
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to logout?'**
  String get confirmLogout;

  /// Cancel button label
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get cancel;

  /// Clear button label
  ///
  /// In en, this message translates to:
  /// **'Clear'**
  String get clear;

  /// Confirm button label
  ///
  /// In en, this message translates to:
  /// **'Confirm'**
  String get confirm;

  /// Save button label
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get save;

  /// Delete button label
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get delete;

  /// Edit button label
  ///
  /// In en, this message translates to:
  /// **'Edit'**
  String get edit;

  /// Add button label
  ///
  /// In en, this message translates to:
  /// **'Add'**
  String get add;

  /// Update button label
  ///
  /// In en, this message translates to:
  /// **'Update'**
  String get update;

  /// Create button label
  ///
  /// In en, this message translates to:
  /// **'Create'**
  String get create;

  /// Search button label
  ///
  /// In en, this message translates to:
  /// **'Search'**
  String get search;

  /// Filter button label
  ///
  /// In en, this message translates to:
  /// **'Filter'**
  String get filter;

  /// Refresh button label
  ///
  /// In en, this message translates to:
  /// **'Refresh'**
  String get refresh;

  /// Loading message
  ///
  /// In en, this message translates to:
  /// **'Loading...'**
  String get loading;

  /// Error label
  ///
  /// In en, this message translates to:
  /// **'Error'**
  String get error;

  /// Success label
  ///
  /// In en, this message translates to:
  /// **'Success'**
  String get success;

  /// Retry button label
  ///
  /// In en, this message translates to:
  /// **'Retry'**
  String get retry;

  /// Close button label
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get close;

  /// OK button label
  ///
  /// In en, this message translates to:
  /// **'OK'**
  String get ok;

  /// Yes button label
  ///
  /// In en, this message translates to:
  /// **'Yes'**
  String get yes;

  /// No button label
  ///
  /// In en, this message translates to:
  /// **'No'**
  String get no;

  /// Welcome message
  ///
  /// In en, this message translates to:
  /// **'Welcome'**
  String get welcome;

  /// Login page welcome title
  ///
  /// In en, this message translates to:
  /// **'Welcome Back'**
  String get auth_welcome_back;

  /// Login page subtitle
  ///
  /// In en, this message translates to:
  /// **'Sign in to continue'**
  String get auth_sign_in_subtitle;

  /// Email field validation message
  ///
  /// In en, this message translates to:
  /// **'Please enter your email'**
  String get auth_enter_email;

  /// Email validation error
  ///
  /// In en, this message translates to:
  /// **'Please enter a valid email'**
  String get auth_enter_valid_email;

  /// Password field validation message
  ///
  /// In en, this message translates to:
  /// **'Please enter your password'**
  String get auth_enter_password;

  /// Password length validation
  ///
  /// In en, this message translates to:
  /// **'Password must be at least 6 characters'**
  String get auth_password_too_short;

  /// Email field label
  ///
  /// In en, this message translates to:
  /// **'Email'**
  String get auth_email;

  /// Password field label
  ///
  /// In en, this message translates to:
  /// **'Password'**
  String get auth_password;

  /// Remember me checkbox label
  ///
  /// In en, this message translates to:
  /// **'Remember me'**
  String get auth_remember_me;

  /// Forgot password link
  ///
  /// In en, this message translates to:
  /// **'Forgot Password?'**
  String get auth_forgot_password;

  /// Login button label
  ///
  /// In en, this message translates to:
  /// **'Sign In'**
  String get auth_login;

  /// No account prompt
  ///
  /// In en, this message translates to:
  /// **'Don\'t have an account?'**
  String get auth_no_account;

  /// Sign up button label
  ///
  /// In en, this message translates to:
  /// **'Sign Up'**
  String get auth_sign_up;

  /// Create account page title
  ///
  /// In en, this message translates to:
  /// **'Create Account'**
  String get auth_create_account;

  /// Sign up page subtitle
  ///
  /// In en, this message translates to:
  /// **'Join us to get started'**
  String get auth_sign_up_subtitle;

  /// Full name field label
  ///
  /// In en, this message translates to:
  /// **'Full Name'**
  String get auth_full_name;

  /// Name field validation
  ///
  /// In en, this message translates to:
  /// **'Please enter your name'**
  String get auth_enter_name;

  /// Confirm password field label
  ///
  /// In en, this message translates to:
  /// **'Confirm Password'**
  String get auth_confirm_password;

  /// Password mismatch error
  ///
  /// In en, this message translates to:
  /// **'Passwords do not match'**
  String get auth_passwords_not_match;

  /// Terms agreement checkbox
  ///
  /// In en, this message translates to:
  /// **'I agree to the Terms and Conditions'**
  String get auth_agree_terms;

  /// Already have account prompt
  ///
  /// In en, this message translates to:
  /// **'Already have an account?'**
  String get auth_already_have_account;

  /// Sign in link label
  ///
  /// In en, this message translates to:
  /// **'Sign In'**
  String get auth_sign_in_link;

  /// Reset password page title
  ///
  /// In en, this message translates to:
  /// **'Reset Password'**
  String get auth_reset_password;

  /// Reset password subtitle
  ///
  /// In en, this message translates to:
  /// **'Enter your email to receive reset instructions'**
  String get auth_reset_password_subtitle;

  /// Send reset link button
  ///
  /// In en, this message translates to:
  /// **'Send Reset Link'**
  String get auth_send_reset_link;

  /// Back to login link
  ///
  /// In en, this message translates to:
  /// **'Back to Login'**
  String get auth_back_to_login;

  /// Reset email sent message
  ///
  /// In en, this message translates to:
  /// **'Password reset email sent'**
  String get auth_reset_email_sent;

  /// Login failed message
  ///
  /// In en, this message translates to:
  /// **'Login failed'**
  String get login_failed;

  /// Registration failed message
  ///
  /// In en, this message translates to:
  /// **'Registration failed'**
  String get register_failed;

  /// Logout failed message
  ///
  /// In en, this message translates to:
  /// **'Logout failed'**
  String get logout_failed;

  /// New chat button label
  ///
  /// In en, this message translates to:
  /// **'New Chat'**
  String get chat_new_chat;

  /// Chat input placeholder
  ///
  /// In en, this message translates to:
  /// **'Type your message...'**
  String get chat_type_message_hint;

  /// AI thinking indicator
  ///
  /// In en, this message translates to:
  /// **'AI is thinking...'**
  String get chat_ai_thinking;

  /// Send message button
  ///
  /// In en, this message translates to:
  /// **'Send'**
  String get chat_send_message;

  /// Clear chat history button
  ///
  /// In en, this message translates to:
  /// **'Clear History'**
  String get chat_clear_history;

  /// Clear history confirmation
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to clear all chat history?'**
  String get chat_confirm_clear;

  /// Empty chat state
  ///
  /// In en, this message translates to:
  /// **'No messages yet'**
  String get chat_no_messages;

  /// Conversation history section
  ///
  /// In en, this message translates to:
  /// **'Conversation History'**
  String get chat_conversation_history;

  /// Today label for history
  ///
  /// In en, this message translates to:
  /// **'Today'**
  String get chat_today;

  /// Yesterday label for history
  ///
  /// In en, this message translates to:
  /// **'Yesterday'**
  String get chat_yesterday;

  /// This week label for history
  ///
  /// In en, this message translates to:
  /// **'This Week'**
  String get chat_this_week;

  /// Older label for history
  ///
  /// In en, this message translates to:
  /// **'Older'**
  String get chat_older;

  /// Assistant settings title
  ///
  /// In en, this message translates to:
  /// **'Assistant Settings'**
  String get assistant_settings;

  /// AI model setting label
  ///
  /// In en, this message translates to:
  /// **'AI Model'**
  String get assistant_model;

  /// Temperature setting label
  ///
  /// In en, this message translates to:
  /// **'Temperature'**
  String get assistant_temperature;

  /// Max tokens setting label
  ///
  /// In en, this message translates to:
  /// **'Max Tokens'**
  String get assistant_max_tokens;

  /// System prompt setting label
  ///
  /// In en, this message translates to:
  /// **'System Prompt'**
  String get assistant_system_prompt;

  /// Temperature description
  ///
  /// In en, this message translates to:
  /// **'Controls randomness in responses'**
  String get assistant_temperature_desc;

  /// Max tokens description
  ///
  /// In en, this message translates to:
  /// **'Maximum length of response'**
  String get assistant_max_tokens_desc;

  /// Knowledge base page title
  ///
  /// In en, this message translates to:
  /// **'Knowledge Base'**
  String get knowledge_base;

  /// My knowledge bases section
  ///
  /// In en, this message translates to:
  /// **'My Knowledge Bases'**
  String get knowledge_my_bases;

  /// Create knowledge base button
  ///
  /// In en, this message translates to:
  /// **'Create Knowledge Base'**
  String get knowledge_create_base;

  /// Knowledge base name field
  ///
  /// In en, this message translates to:
  /// **'Knowledge Base Name'**
  String get knowledge_base_name;

  /// Knowledge base name placeholder
  ///
  /// In en, this message translates to:
  /// **'Enter knowledge base name'**
  String get knowledge_enter_name;

  /// Description field label
  ///
  /// In en, this message translates to:
  /// **'Description'**
  String get knowledge_description;

  /// Description placeholder
  ///
  /// In en, this message translates to:
  /// **'Enter description'**
  String get knowledge_enter_description;

  /// Upload document button
  ///
  /// In en, this message translates to:
  /// **'Upload Document'**
  String get knowledge_upload_document;

  /// Empty knowledge bases state
  ///
  /// In en, this message translates to:
  /// **'No knowledge bases yet'**
  String get knowledge_no_bases;

  /// Create first knowledge base prompt
  ///
  /// In en, this message translates to:
  /// **'Create your first knowledge base'**
  String get knowledge_create_first;

  /// Documents section label
  ///
  /// In en, this message translates to:
  /// **'Documents'**
  String get knowledge_documents;

  /// No documents state
  ///
  /// In en, this message translates to:
  /// **'No documents uploaded'**
  String get knowledge_no_documents;

  /// Upload first document prompt
  ///
  /// In en, this message translates to:
  /// **'Upload your first document'**
  String get knowledge_upload_first;

  /// Podcast subscriptions page title
  ///
  /// In en, this message translates to:
  /// **'Podcast Subscriptions'**
  String get podcast_subscriptions;

  /// My subscriptions section
  ///
  /// In en, this message translates to:
  /// **'My Subscriptions'**
  String get podcast_my_subscriptions;

  /// Add subscription button
  ///
  /// In en, this message translates to:
  /// **'Add Subscription'**
  String get podcast_add_subscription;

  /// Feed URL field label
  ///
  /// In en, this message translates to:
  /// **'Feed URL'**
  String get podcast_feed_url;

  /// Feed URL placeholder
  ///
  /// In en, this message translates to:
  /// **'Enter podcast feed URL'**
  String get podcast_enter_feed_url;

  /// Invalid URL error
  ///
  /// In en, this message translates to:
  /// **'Please enter a valid URL'**
  String get podcast_invalid_url;

  /// Episodes label
  ///
  /// In en, this message translates to:
  /// **'Episodes'**
  String get podcast_episodes;

  /// Latest episodes section
  ///
  /// In en, this message translates to:
  /// **'Latest Episodes'**
  String get podcast_latest_episodes;

  /// No subscriptions state
  ///
  /// In en, this message translates to:
  /// **'No subscriptions yet'**
  String get podcast_no_subscriptions;

  /// Add first podcast prompt
  ///
  /// In en, this message translates to:
  /// **'Add your first podcast'**
  String get podcast_add_first;

  /// Play button
  ///
  /// In en, this message translates to:
  /// **'Play'**
  String get podcast_play;

  /// Pause button label
  ///
  /// In en, this message translates to:
  /// **'Pause'**
  String get podcast_pause;

  /// Duration label
  ///
  /// In en, this message translates to:
  /// **'Duration'**
  String get podcast_duration;

  /// Published date label
  ///
  /// In en, this message translates to:
  /// **'Published'**
  String get podcast_published;

  /// AI Models page title
  ///
  /// In en, this message translates to:
  /// **'AI Models'**
  String get ai_models;

  /// Available models section
  ///
  /// In en, this message translates to:
  /// **'Available Models'**
  String get ai_available_models;

  /// Model name label
  ///
  /// In en, this message translates to:
  /// **'Model Name'**
  String get ai_model_name;

  /// Provider label
  ///
  /// In en, this message translates to:
  /// **'Provider'**
  String get ai_provider;

  /// Model type label
  ///
  /// In en, this message translates to:
  /// **'Model Type'**
  String get ai_model_type;

  /// Model details section
  ///
  /// In en, this message translates to:
  /// **'Model Details'**
  String get ai_model_details;

  /// Select model button
  ///
  /// In en, this message translates to:
  /// **'Select Model'**
  String get ai_select_model;

  /// Model selected message
  ///
  /// In en, this message translates to:
  /// **'Model selected'**
  String get ai_model_selected;

  /// No models state
  ///
  /// In en, this message translates to:
  /// **'No models available'**
  String get ai_no_models;

  /// Home page title
  ///
  /// In en, this message translates to:
  /// **'Home'**
  String get home;

  /// Navigation item: Assistant
  ///
  /// In en, this message translates to:
  /// **'Assistant'**
  String get nav_assistant;

  /// Navigation item: Knowledge
  ///
  /// In en, this message translates to:
  /// **'Knowledge'**
  String get nav_knowledge;

  /// Navigation item: Feed
  ///
  /// In en, this message translates to:
  /// **'Feed'**
  String get nav_feed;

  /// Navigation item: Podcast
  ///
  /// In en, this message translates to:
  /// **'Podcast'**
  String get nav_podcast;

  /// Navigation item: Chat
  ///
  /// In en, this message translates to:
  /// **'Chat'**
  String get nav_chat;

  /// Navigation item: Profile
  ///
  /// In en, this message translates to:
  /// **'Profile'**
  String get nav_profile;

  /// Podcast feed page title
  ///
  /// In en, this message translates to:
  /// **'Feed'**
  String get podcast_feed_page_title;

  /// Refresh feed button tooltip
  ///
  /// In en, this message translates to:
  /// **'Refresh Feed'**
  String get podcast_refresh_feed;

  /// Add podcast button
  ///
  /// In en, this message translates to:
  /// **'Add Podcast'**
  String get podcast_add_podcast;

  /// Bulk import button
  ///
  /// In en, this message translates to:
  /// **'Bulk Import'**
  String get podcast_bulk_import;

  /// Failed to load feed error message
  ///
  /// In en, this message translates to:
  /// **'Failed to load feed'**
  String get podcast_failed_to_load_feed;

  /// Retry button
  ///
  /// In en, this message translates to:
  /// **'Retry'**
  String get podcast_retry;

  /// No episodes state
  ///
  /// In en, this message translates to:
  /// **'No episodes found'**
  String get podcast_no_episodes_found;

  /// Bookmark button
  ///
  /// In en, this message translates to:
  /// **'Bookmark'**
  String get podcast_bookmark;

  /// Share button
  ///
  /// In en, this message translates to:
  /// **'Share'**
  String get podcast_share;

  /// Default podcast name
  ///
  /// In en, this message translates to:
  /// **'Podcast'**
  String get podcast_default_podcast;

  /// Navigation item: AI Models
  ///
  /// In en, this message translates to:
  /// **'AI Models'**
  String get nav_ai_models;

  /// Navigation item: Settings
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get nav_settings;

  /// Required field validation
  ///
  /// In en, this message translates to:
  /// **'This field is required'**
  String get validation_required;

  /// Invalid email validation
  ///
  /// In en, this message translates to:
  /// **'Invalid email format'**
  String get validation_invalid_email;

  /// Invalid URL validation
  ///
  /// In en, this message translates to:
  /// **'Invalid URL format'**
  String get validation_invalid_url;

  /// Too short validation
  ///
  /// In en, this message translates to:
  /// **'Too short'**
  String get validation_too_short;

  /// Too long validation
  ///
  /// In en, this message translates to:
  /// **'Too long'**
  String get validation_too_long;

  /// Network error message
  ///
  /// In en, this message translates to:
  /// **'Network error. Please check your connection.'**
  String get network_error;

  /// Server error message
  ///
  /// In en, this message translates to:
  /// **'Server error. Please try again later.'**
  String get server_error;

  /// Unknown error message
  ///
  /// In en, this message translates to:
  /// **'An unknown error occurred'**
  String get unknown_error;

  /// Request timeout message
  ///
  /// In en, this message translates to:
  /// **'Request timeout. Please try again.'**
  String get request_timeout;

  /// Unauthorized error message
  ///
  /// In en, this message translates to:
  /// **'Unauthorized. Please login again.'**
  String get unauthorized;

  /// Forbidden error message
  ///
  /// In en, this message translates to:
  /// **'Access denied'**
  String get forbidden;

  /// Not found error message
  ///
  /// In en, this message translates to:
  /// **'Resource not found'**
  String get not_found;

  /// Session expired message
  ///
  /// In en, this message translates to:
  /// **'Session expired. Please login again.'**
  String get session_expired;

  /// Generic success message
  ///
  /// In en, this message translates to:
  /// **'Action completed successfully'**
  String get action_completed;

  /// Generic failure message
  ///
  /// In en, this message translates to:
  /// **'Action failed'**
  String get action_failed;

  /// Delete confirmation title
  ///
  /// In en, this message translates to:
  /// **'Delete Item'**
  String get delete_confirm_title;

  /// Delete confirmation message
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to delete this item? This action cannot be undone.'**
  String get delete_confirm_message;

  /// No data state message
  ///
  /// In en, this message translates to:
  /// **'No data available'**
  String get no_data;

  /// Pull to refresh hint
  ///
  /// In en, this message translates to:
  /// **'Pull to refresh'**
  String get pull_to_refresh;

  /// Release to refresh hint
  ///
  /// In en, this message translates to:
  /// **'Release to refresh'**
  String get release_to_refresh;

  /// Refreshing message
  ///
  /// In en, this message translates to:
  /// **'Refreshing...'**
  String get refreshing;

  /// Empty list message
  ///
  /// In en, this message translates to:
  /// **'No items to display'**
  String get empty_list;

  /// No search results message
  ///
  /// In en, this message translates to:
  /// **'No results found'**
  String get no_results;

  /// Different search suggestion
  ///
  /// In en, this message translates to:
  /// **'Try a different search term'**
  String get try_different_search;

  /// Podcasts page title
  ///
  /// In en, this message translates to:
  /// **'Podcasts'**
  String get podcast_title;

  /// No podcasts state
  ///
  /// In en, this message translates to:
  /// **'No podcasts yet'**
  String get podcast_no_podcasts;

  /// No description label
  ///
  /// In en, this message translates to:
  /// **'No description'**
  String get podcast_description;

  /// Updated date prefix
  ///
  /// In en, this message translates to:
  /// **'Updated:'**
  String get podcast_updated;

  /// Failed to load subscriptions error
  ///
  /// In en, this message translates to:
  /// **'Failed to load subscriptions'**
  String get podcast_failed_load_subscriptions;

  /// Unknown episode title
  ///
  /// In en, this message translates to:
  /// **'Unknown Episode'**
  String get podcast_player_unknown_episode;

  /// No audio link message
  ///
  /// In en, this message translates to:
  /// **'No audio link'**
  String get podcast_player_no_audio;

  /// Coming soon label
  ///
  /// In en, this message translates to:
  /// **'Coming Soon'**
  String get podcast_coming_soon;

  /// Filter all episodes
  ///
  /// In en, this message translates to:
  /// **'All'**
  String get podcast_filter_all;

  /// Filter unplayed episodes
  ///
  /// In en, this message translates to:
  /// **'Unplayed'**
  String get podcast_filter_unplayed;

  /// Filter played episodes
  ///
  /// In en, this message translates to:
  /// **'Played'**
  String get podcast_filter_played;

  /// Filter episodes with AI summary
  ///
  /// In en, this message translates to:
  /// **'With AI Summary'**
  String get podcast_filter_with_summary;

  /// Mark all as played option
  ///
  /// In en, this message translates to:
  /// **'Mark All as Played'**
  String get podcast_mark_all_played;

  /// Mark all as unplayed option
  ///
  /// In en, this message translates to:
  /// **'Mark All as Unplayed'**
  String get podcast_mark_all_unplayed;

  /// No episodes state
  ///
  /// In en, this message translates to:
  /// **'No Episodes Found'**
  String get podcast_no_episodes;

  /// No episodes with summary state
  ///
  /// In en, this message translates to:
  /// **'No Episodes with AI Summary'**
  String get podcast_no_episodes_with_summary;

  /// Try adjusting filters hint
  ///
  /// In en, this message translates to:
  /// **'Try adjusting your filters'**
  String get podcast_try_adjusting_filters;

  /// No episodes yet message
  ///
  /// In en, this message translates to:
  /// **'This podcast might not have any episodes yet'**
  String get podcast_no_episodes_yet;

  /// Failed to load episodes error
  ///
  /// In en, this message translates to:
  /// **'Failed to Load Episodes'**
  String get podcast_failed_load_episodes;

  /// Filter episodes dialog title
  ///
  /// In en, this message translates to:
  /// **'Filter Episodes'**
  String get podcast_filter_episodes;

  /// Playback status label
  ///
  /// In en, this message translates to:
  /// **'Playback Status:'**
  String get podcast_playback_status;

  /// All episodes filter option
  ///
  /// In en, this message translates to:
  /// **'All Episodes'**
  String get podcast_all_episodes;

  /// Unplayed only filter option
  ///
  /// In en, this message translates to:
  /// **'Unplayed Only'**
  String get podcast_unplayed_only;

  /// Played only filter option
  ///
  /// In en, this message translates to:
  /// **'Played Only'**
  String get podcast_played_only;

  /// Only with summary filter option
  ///
  /// In en, this message translates to:
  /// **'Only episodes with AI Summary'**
  String get podcast_only_with_summary;

  /// Apply button label
  ///
  /// In en, this message translates to:
  /// **'Apply'**
  String get podcast_apply;

  /// Add podcast dialog title
  ///
  /// In en, this message translates to:
  /// **'Add Podcast'**
  String get podcast_add_dialog_title;

  /// RSS Feed URL field label
  ///
  /// In en, this message translates to:
  /// **'RSS Feed URL'**
  String get podcast_rss_feed_url;

  /// Feed URL hint
  ///
  /// In en, this message translates to:
  /// **'https://example.com/feed.xml'**
  String get podcast_feed_url_hint;

  /// Enter URL validation
  ///
  /// In en, this message translates to:
  /// **'Please enter a URL'**
  String get podcast_enter_url;

  /// Podcast added success message
  ///
  /// In en, this message translates to:
  /// **'Podcast added successfully!'**
  String get podcast_added_successfully;

  /// Failed to add podcast error
  ///
  /// In en, this message translates to:
  /// **'Failed to add podcast:'**
  String get podcast_failed_add;

  /// Need to add many prompt
  ///
  /// In en, this message translates to:
  /// **'Need to add many?'**
  String get podcast_need_many;

  /// Adding podcast loading text
  ///
  /// In en, this message translates to:
  /// **'Adding...'**
  String get podcast_adding;

  /// AI Model Management page title
  ///
  /// In en, this message translates to:
  /// **'AI Model Management'**
  String get ai_model_management;

  /// Add model button
  ///
  /// In en, this message translates to:
  /// **'Add Model'**
  String get ai_add_model;

  /// Edit model button
  ///
  /// In en, this message translates to:
  /// **'Edit Model'**
  String get ai_edit_model;

  /// Delete model button
  ///
  /// In en, this message translates to:
  /// **'Delete Model'**
  String get ai_delete_model;

  /// Test model button
  ///
  /// In en, this message translates to:
  /// **'Test Model'**
  String get ai_test_model;

  /// Model name placeholder
  ///
  /// In en, this message translates to:
  /// **'e.g., GPT-4'**
  String get ai_model_name_placeholder;

  /// Provider name field
  ///
  /// In en, this message translates to:
  /// **'Provider Name'**
  String get ai_provider_name;

  /// API Key field
  ///
  /// In en, this message translates to:
  /// **'API Key'**
  String get ai_api_key;

  /// API Base URL field
  ///
  /// In en, this message translates to:
  /// **'API Base URL'**
  String get ai_api_base;

  /// Enter model name validation
  ///
  /// In en, this message translates to:
  /// **'Please enter model name'**
  String get ai_enter_model_name;

  /// Enter provider validation
  ///
  /// In en, this message translates to:
  /// **'Please enter provider name'**
  String get ai_enter_provider;

  /// Enter API key validation
  ///
  /// In en, this message translates to:
  /// **'Please enter API key'**
  String get ai_enter_api_key;

  /// No models state
  ///
  /// In en, this message translates to:
  /// **'No AI models configured'**
  String get ai_no_models_configured;

  /// Add first model prompt
  ///
  /// In en, this message translates to:
  /// **'Add your first AI model'**
  String get ai_add_first_model;

  /// Model added success
  ///
  /// In en, this message translates to:
  /// **'Model added successfully'**
  String get ai_model_added;

  /// Model updated success
  ///
  /// In en, this message translates to:
  /// **'Model updated successfully'**
  String get ai_model_updated;

  /// Model deleted success
  ///
  /// In en, this message translates to:
  /// **'Model deleted successfully'**
  String get ai_model_deleted;

  /// Confirm delete model
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to delete this model?'**
  String get ai_confirm_delete_model;

  /// Test prompt placeholder
  ///
  /// In en, this message translates to:
  /// **'Test prompt'**
  String get ai_test_prompt;

  /// Send test button
  ///
  /// In en, this message translates to:
  /// **'Send Test'**
  String get ai_send_test;

  /// Test response label
  ///
  /// In en, this message translates to:
  /// **'Test Response'**
  String get ai_test_response;

  /// Create model dialog title
  ///
  /// In en, this message translates to:
  /// **'Create AI Model Config'**
  String get ai_create_model_config;

  /// Config name field
  ///
  /// In en, this message translates to:
  /// **'Config Name'**
  String get ai_config_name;

  /// Base URL field
  ///
  /// In en, this message translates to:
  /// **'Base URL'**
  String get ai_base_url;

  /// Base URL hint
  ///
  /// In en, this message translates to:
  /// **'https://api.openai.com/v1'**
  String get ai_base_url_hint;

  /// Model name field
  ///
  /// In en, this message translates to:
  /// **'Model Name'**
  String get ai_model_name_field;

  /// Model ID hint
  ///
  /// In en, this message translates to:
  /// **'e.g. gpt-4o'**
  String get ai_model_id_hint;

  /// Config name hint
  ///
  /// In en, this message translates to:
  /// **'e.g. My GPT-4o'**
  String get ai_config_name_hint;

  /// Enter config name validation
  ///
  /// In en, this message translates to:
  /// **'Please enter a config name'**
  String get ai_enter_config_name;

  /// Enter base URL validation
  ///
  /// In en, this message translates to:
  /// **'Please enter Base URL'**
  String get ai_enter_base_url;

  /// Enter model ID validation
  ///
  /// In en, this message translates to:
  /// **'Please enter Model Name'**
  String get ai_enter_model_id;

  /// Transcription model type
  ///
  /// In en, this message translates to:
  /// **'Transcription Model'**
  String get ai_transcription_model;

  /// Text generation model type
  ///
  /// In en, this message translates to:
  /// **'Text Generation Model'**
  String get ai_text_generation_model;

  /// Model type label
  ///
  /// In en, this message translates to:
  /// **'Model Type:'**
  String get ai_model_type_label;

  /// Only show active toggle
  ///
  /// In en, this message translates to:
  /// **'Only Show Active'**
  String get ai_only_show_active;

  /// Search models placeholder
  ///
  /// In en, this message translates to:
  /// **'Search model name, description...'**
  String get ai_search_models;

  /// Model created success
  ///
  /// In en, this message translates to:
  /// **'Model \'{name}\' created successfully'**
  String ai_model_created(Object name);

  /// Model updated success
  ///
  /// In en, this message translates to:
  /// **'Model \'{name}\' updated successfully'**
  String ai_model_updated_msg(Object name);

  /// Model deleted success
  ///
  /// In en, this message translates to:
  /// **'Model \'{name}\' deleted'**
  String ai_model_deleted_msg(Object name);

  /// Set as default success message
  ///
  /// In en, this message translates to:
  /// **'Set \'{name}\' as default model'**
  String ai_set_as_default_success(Object name);

  /// Model enabled message
  ///
  /// In en, this message translates to:
  /// **'Model enabled'**
  String get ai_model_enabled;

  /// Model disabled message
  ///
  /// In en, this message translates to:
  /// **'Model disabled'**
  String get ai_model_disabled;

  /// Operation failed message
  ///
  /// In en, this message translates to:
  /// **'Operation failed'**
  String get ai_operation_failed;

  /// Set default failed
  ///
  /// In en, this message translates to:
  /// **'Failed to set as default model'**
  String get ai_set_default_failed;

  /// Delete failed
  ///
  /// In en, this message translates to:
  /// **'Delete failed'**
  String get ai_delete_failed;

  /// Load failed error
  ///
  /// In en, this message translates to:
  /// **'Load failed: {error}'**
  String ai_load_failed(Object error);

  /// No models state
  ///
  /// In en, this message translates to:
  /// **'No model configurations yet'**
  String get ai_no_models_configured_yet;

  /// Add first model button
  ///
  /// In en, this message translates to:
  /// **'Add first model'**
  String get ai_add_first_model_btn;

  /// Guest user label when not logged in
  ///
  /// In en, this message translates to:
  /// **'Guest User'**
  String get profile_guest_user;

  /// Please log in message
  ///
  /// In en, this message translates to:
  /// **'Please log in'**
  String get profile_please_login;

  /// Premium badge label
  ///
  /// In en, this message translates to:
  /// **'Premium'**
  String get profile_premium;

  /// Verified badge label
  ///
  /// In en, this message translates to:
  /// **'Verified'**
  String get profile_verified;

  /// Account settings section
  ///
  /// In en, this message translates to:
  /// **'Account Settings'**
  String get profile_account_settings;

  /// Edit profile button/title
  ///
  /// In en, this message translates to:
  /// **'Edit Profile'**
  String get profile_edit_profile;

  /// Edit profile subtitle
  ///
  /// In en, this message translates to:
  /// **'Update your personal information'**
  String get profile_edit_profile_subtitle;

  /// Security settings
  ///
  /// In en, this message translates to:
  /// **'Security'**
  String get profile_security;

  /// Security settings subtitle
  ///
  /// In en, this message translates to:
  /// **'Password, authentication, and privacy'**
  String get profile_security_subtitle;

  /// Notifications settings
  ///
  /// In en, this message translates to:
  /// **'Notifications'**
  String get profile_notifications;

  /// Notifications subtitle
  ///
  /// In en, this message translates to:
  /// **'Push notifications and email alerts'**
  String get profile_notifications_subtitle;

  /// Dark mode toggle
  ///
  /// In en, this message translates to:
  /// **'Dark Mode'**
  String get profile_dark_mode;

  /// Dark mode subtitle
  ///
  /// In en, this message translates to:
  /// **'Toggle dark theme'**
  String get profile_dark_mode_subtitle;

  /// Auto sync toggle
  ///
  /// In en, this message translates to:
  /// **'Auto Sync'**
  String get profile_auto_sync;

  /// Auto sync subtitle
  ///
  /// In en, this message translates to:
  /// **'Automatically sync data across devices'**
  String get profile_auto_sync_subtitle;

  /// Help center title
  ///
  /// In en, this message translates to:
  /// **'Help Center'**
  String get profile_help_center;

  /// Help center subtitle
  ///
  /// In en, this message translates to:
  /// **'Get help and support'**
  String get profile_help_center_subtitle;

  /// About subtitle
  ///
  /// In en, this message translates to:
  /// **'App version and information'**
  String get profile_about_subtitle;

  /// Name field label
  ///
  /// In en, this message translates to:
  /// **'Name'**
  String get profile_name;

  /// Email field label in profile
  ///
  /// In en, this message translates to:
  /// **'Email'**
  String get profile_email_field;

  /// Bio field label
  ///
  /// In en, this message translates to:
  /// **'Bio'**
  String get profile_bio;

  /// Profile updated success message
  ///
  /// In en, this message translates to:
  /// **'Profile updated successfully'**
  String get profile_updated_successfully;

  /// Change password option
  ///
  /// In en, this message translates to:
  /// **'Change Password'**
  String get profile_change_password;

  /// Biometric authentication option
  ///
  /// In en, this message translates to:
  /// **'Biometric Authentication'**
  String get profile_biometric_auth;

  /// Two-factor authentication option
  ///
  /// In en, this message translates to:
  /// **'Two-Factor Authentication'**
  String get profile_two_factor_auth;

  /// User guide option
  ///
  /// In en, this message translates to:
  /// **'User Guide'**
  String get profile_user_guide;

  /// User guide subtitle
  ///
  /// In en, this message translates to:
  /// **'Learn how to use the app'**
  String get profile_user_guide_subtitle;

  /// Video tutorials option
  ///
  /// In en, this message translates to:
  /// **'Video Tutorials'**
  String get profile_video_tutorials;

  /// Video tutorials subtitle
  ///
  /// In en, this message translates to:
  /// **'Watch step-by-step guides'**
  String get profile_video_tutorials_subtitle;

  /// Contact support option
  ///
  /// In en, this message translates to:
  /// **'Contact Support'**
  String get profile_contact_support;

  /// Contact support subtitle
  ///
  /// In en, this message translates to:
  /// **'Get help from our team'**
  String get profile_contact_support_subtitle;

  /// Logout dialog title
  ///
  /// In en, this message translates to:
  /// **'Logout'**
  String get profile_logout_title;

  /// Logout confirmation message
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to logout?'**
  String get profile_logout_message;

  /// Logged out success message
  ///
  /// In en, this message translates to:
  /// **'Logged out successfully'**
  String get profile_logged_out;

  /// Error loading profile message
  ///
  /// In en, this message translates to:
  /// **'Error loading profile'**
  String get profile_error_loading;

  /// Settings saved success message
  ///
  /// In en, this message translates to:
  /// **'Settings saved successfully!'**
  String get settings_saved_successfully;

  /// AI Text Generation Model section
  ///
  /// In en, this message translates to:
  /// **'AI Text Generation Model'**
  String get settings_ai_text_generation;

  /// Config label
  ///
  /// In en, this message translates to:
  /// **'Config'**
  String get settings_config;

  /// Add new config option
  ///
  /// In en, this message translates to:
  /// **'Add New...'**
  String get settings_add_new;

  /// Edit config tooltip
  ///
  /// In en, this message translates to:
  /// **'Edit Config'**
  String get settings_edit_config;

  /// Delete config tooltip
  ///
  /// In en, this message translates to:
  /// **'Delete Config'**
  String get settings_delete_config;

  /// Test connection button
  ///
  /// In en, this message translates to:
  /// **'Test Connection'**
  String get settings_test_connection;

  /// API Base URL label
  ///
  /// In en, this message translates to:
  /// **'API Base URL'**
  String get settings_api_base_url;

  /// AI model info message
  ///
  /// In en, this message translates to:
  /// **'This model will be used for AI tasks. Select or create a configuration above.'**
  String get settings_model_info_ai_tasks;

  /// Audio Transcription Model section
  ///
  /// In en, this message translates to:
  /// **'Audio Transcription Model'**
  String get settings_audio_transcription;

  /// API URL label
  ///
  /// In en, this message translates to:
  /// **'API URL'**
  String get settings_api_url;

  /// Transcription API key hint
  ///
  /// In en, this message translates to:
  /// **'Enter your transcription API key'**
  String get settings_transcription_api_key_hint;

  /// Transcription model info message
  ///
  /// In en, this message translates to:
  /// **'This model will be used for transcribing podcast audio to text.'**
  String get settings_model_info_transcription;

  /// Processing Settings section
  ///
  /// In en, this message translates to:
  /// **'Processing Settings'**
  String get settings_processing;

  /// Audio chunk size label
  ///
  /// In en, this message translates to:
  /// **'Audio Chunk Size'**
  String get settings_audio_chunk_size;

  /// MB per chunk label
  ///
  /// In en, this message translates to:
  /// **'{mb}MB per chunk'**
  String settings_mb_per_chunk(Object mb);

  /// Max concurrent threads label
  ///
  /// In en, this message translates to:
  /// **'Max Concurrent Threads'**
  String get settings_max_threads;

  /// Threads label
  ///
  /// In en, this message translates to:
  /// **'{threads} threads'**
  String settings_threads(Object threads);

  /// RSS Subscription Settings section
  ///
  /// In en, this message translates to:
  /// **'RSS Subscription Settings'**
  String get settings_rss_subscription;

  /// RSS Schedule Configuration option
  ///
  /// In en, this message translates to:
  /// **'RSS Schedule Configuration'**
  String get settings_rss_schedule_config;

  /// RSS schedule subtitle
  ///
  /// In en, this message translates to:
  /// **'Manage update frequency and schedule for all RSS subscriptions'**
  String get settings_rss_schedule_subtitle;

  /// App version label
  ///
  /// In en, this message translates to:
  /// **'App Version'**
  String get settings_app_version;

  /// Backend API Documentation option
  ///
  /// In en, this message translates to:
  /// **'Backend API Documentation'**
  String get settings_backend_api_docs;

  /// Backend API docs subtitle
  ///
  /// In en, this message translates to:
  /// **'View API docs and endpoints'**
  String get settings_backend_api_docs_subtitle;

  /// API Documentation dialog title
  ///
  /// In en, this message translates to:
  /// **'API Documentation'**
  String get settings_api_documentation;

  /// Text Generation endpoint name
  ///
  /// In en, this message translates to:
  /// **'Text Generation'**
  String get settings_text_generation;

  /// Transcription endpoint name
  ///
  /// In en, this message translates to:
  /// **'Transcription'**
  String get settings_transcription_endpoint;

  /// Settings endpoint name
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get settings_user_settings_endpoint;

  /// Config env vars label
  ///
  /// In en, this message translates to:
  /// **'Configuration Environment Variables:'**
  String get settings_config_env_vars;

  /// OpenAI API key env var
  ///
  /// In en, this message translates to:
  /// **'OpenAI API key'**
  String get settings_openai_api_key;

  /// API base URL env var
  ///
  /// In en, this message translates to:
  /// **'API base URL'**
  String get settings_openai_api_base_url;

  /// Transcription API URL env var
  ///
  /// In en, this message translates to:
  /// **'Transcription API URL'**
  String get settings_transcription_api_url;

  /// Transcription API key env var
  ///
  /// In en, this message translates to:
  /// **'Transcription API key'**
  String get settings_transcription_api_key_env;

  /// Transcription model name env var
  ///
  /// In en, this message translates to:
  /// **'Transcription model name'**
  String get settings_transcription_model_name;

  /// Summary model name env var
  ///
  /// In en, this message translates to:
  /// **'AI summary model name'**
  String get settings_summary_model;

  /// Enter API URL validation
  ///
  /// In en, this message translates to:
  /// **'Please enter API URL'**
  String get settings_enter_api_url;

  /// Enter API Key validation
  ///
  /// In en, this message translates to:
  /// **'Please enter API Key'**
  String get settings_enter_api_key;

  /// Enter Model Name validation
  ///
  /// In en, this message translates to:
  /// **'Please enter Model Name'**
  String get settings_enter_model_name_validation;

  /// Testing connection message
  ///
  /// In en, this message translates to:
  /// **'Testing connection...'**
  String get settings_testing_connection;

  /// Connection successful title
  ///
  /// In en, this message translates to:
  /// **'Connection Successful'**
  String get settings_connection_successful;

  /// Connection failed title
  ///
  /// In en, this message translates to:
  /// **'Connection Failed'**
  String get settings_connection_failed;

  /// Response time label
  ///
  /// In en, this message translates to:
  /// **'Response Time: {ms}ms'**
  String settings_response_time(Object ms);

  /// Test response label
  ///
  /// In en, this message translates to:
  /// **'Test Response:'**
  String get settings_test_response;

  /// Error message label
  ///
  /// In en, this message translates to:
  /// **'Error Message:'**
  String get settings_error_message;

  /// Unknown error message
  ///
  /// In en, this message translates to:
  /// **'Unknown error occurred'**
  String get settings_unknown_error;

  /// Connection error title
  ///
  /// In en, this message translates to:
  /// **'Connection Error'**
  String get settings_connection_error;

  /// Unexpected error message
  ///
  /// In en, this message translates to:
  /// **'An unexpected error occurred:'**
  String get settings_unexpected_error;

  /// Delete confirm title
  ///
  /// In en, this message translates to:
  /// **'Confirm Delete'**
  String get settings_delete_confirm_title;

  /// Delete confirm message
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to delete model \"{name}\"? This will affect all features using this model.'**
  String settings_delete_confirm_message(Object name);

  /// Model deleted message
  ///
  /// In en, this message translates to:
  /// **'Model \"{name}\" deleted'**
  String settings_model_deleted(Object name);

  /// Delete failed message
  ///
  /// In en, this message translates to:
  /// **'Delete failed'**
  String get settings_delete_failed_msg;

  /// Model enabled/disabled message
  ///
  /// In en, this message translates to:
  /// **'Model {status}'**
  String settings_model_enabled_disabled(Object status);

  /// Operation failed message
  ///
  /// In en, this message translates to:
  /// **'Operation failed'**
  String get settings_operation_failed_msg;

  /// Set default success message
  ///
  /// In en, this message translates to:
  /// **'Set \"{name}\" as default model'**
  String settings_set_default_success(Object name);

  /// Set default failed message
  ///
  /// In en, this message translates to:
  /// **'Failed to set as default model'**
  String get settings_set_default_failed_msg;

  /// Load models failed message
  ///
  /// In en, this message translates to:
  /// **'Failed to load models: {error}'**
  String settings_load_models_failed(Object error);

  /// Invalid navigation arguments error
  ///
  /// In en, this message translates to:
  /// **'Invalid navigation arguments'**
  String get invalid_navigation_arguments;

  /// Invalid episode ID error
  ///
  /// In en, this message translates to:
  /// **'Invalid episode ID'**
  String get invalid_episode_id;

  /// Backend API server configuration dialog title
  ///
  /// In en, this message translates to:
  /// **'Backend API Server Configuration'**
  String get backend_api_server_config;

  /// Backend API URL label
  ///
  /// In en, this message translates to:
  /// **'Backend API URL'**
  String get backend_api_url_label;

  /// Backend API URL hint text
  ///
  /// In en, this message translates to:
  /// **'https://api.example.com\\nor http://192.168.1.10:8080'**
  String get backend_api_url_hint;

  /// Backend API description
  ///
  /// In en, this message translates to:
  /// **'Note: This is the backend API server, not related to AI model API'**
  String get backend_api_description;

  /// Use local URL button label
  ///
  /// In en, this message translates to:
  /// **'Local Server'**
  String get use_local_url;

  /// Connection error hint text
  ///
  /// In en, this message translates to:
  /// **'Connection error'**
  String get connection_error_hint;

  /// Connection status - not verified yet
  ///
  /// In en, this message translates to:
  /// **'Unverified'**
  String get connection_status_unverified;

  /// Connection status - currently verifying
  ///
  /// In en, this message translates to:
  /// **'Verifying...'**
  String get connection_status_verifying;

  /// Connection status - successful connection
  ///
  /// In en, this message translates to:
  /// **'Success'**
  String get connection_status_success;

  /// Connection status - connection failed
  ///
  /// In en, this message translates to:
  /// **'Failed'**
  String get connection_status_failed;

  /// Server history title
  ///
  /// In en, this message translates to:
  /// **'History'**
  String get server_history_title;

  /// No server history message
  ///
  /// In en, this message translates to:
  /// **'No history'**
  String get server_history_empty;

  /// Connection success message
  ///
  /// In en, this message translates to:
  /// **'Connected Successfully'**
  String get connected_successfully;

  /// Save failed error message
  ///
  /// In en, this message translates to:
  /// **'Save failed: {error}'**
  String save_failed(Object error);

  /// Restore defaults button label
  ///
  /// In en, this message translates to:
  /// **'Restore Defaults'**
  String get restore_defaults;

  /// Restore defaults confirmation message
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to restore the default server address?'**
  String get restore_defaults_confirmation;

  /// Restore defaults success message
  ///
  /// In en, this message translates to:
  /// **'Restored default server address'**
  String get restore_defaults_success;

  /// Default server address label
  ///
  /// In en, this message translates to:
  /// **'Default server address'**
  String get default_server_address;

  /// Message copied confirmation
  ///
  /// In en, this message translates to:
  /// **'Message copied to clipboard'**
  String get message_copied;

  /// Regenerating response message
  ///
  /// In en, this message translates to:
  /// **'Regenerating response...'**
  String get regenerating_response;

  /// Chat mode coming soon message
  ///
  /// In en, this message translates to:
  /// **'Chat mode selector coming soon!'**
  String get chat_mode_coming_soon;

  /// Voice input coming soon message
  ///
  /// In en, this message translates to:
  /// **'Voice input coming soon!'**
  String get voice_input_coming_soon;

  /// Drop files hint
  ///
  /// In en, this message translates to:
  /// **'Drop files here!'**
  String get drop_files_here;

  /// Set as default button label
  ///
  /// In en, this message translates to:
  /// **'Set as default'**
  String get set_as_default;

  /// Test content label
  ///
  /// In en, this message translates to:
  /// **'Test Content'**
  String get test_content;

  /// Enter test content hint
  ///
  /// In en, this message translates to:
  /// **'Enter test content...'**
  String get enter_test_content;

  /// Server configuration dialog title
  ///
  /// In en, this message translates to:
  /// **'Server Configuration'**
  String get server_config_title;

  /// Server config description
  ///
  /// In en, this message translates to:
  /// **'Enter API Base URL:'**
  String get server_config_description;

  /// Server URL hint text
  ///
  /// In en, this message translates to:
  /// **'http://localhost:8000'**
  String get server_config_hint;

  /// Server config saved message
  ///
  /// In en, this message translates to:
  /// **'Server URL updated. Please restart app if issues persist.'**
  String get server_config_saved;

  /// Floating player accessibility label
  ///
  /// In en, this message translates to:
  /// **'Podcast playback control'**
  String get floating_player_label;

  /// Floating player tooltip
  ///
  /// In en, this message translates to:
  /// **'Play/Pause - Long-press to open player'**
  String get floating_player_tooltip;

  /// Floating player navigation hint
  ///
  /// In en, this message translates to:
  /// **'Long-press to open player'**
  String get floating_player_nav_hint;

  /// Title for bulk selection mode
  ///
  /// In en, this message translates to:
  /// **'Select Podcasts'**
  String get podcast_bulk_select_mode;

  /// Tooltip to enter selection mode
  ///
  /// In en, this message translates to:
  /// **'Select Mode'**
  String get podcast_enter_select_mode;

  /// Deselect all tooltip
  ///
  /// In en, this message translates to:
  /// **'Deselect All'**
  String get podcast_deselect_all;

  /// Bulk delete action label
  ///
  /// In en, this message translates to:
  /// **'Bulk Delete'**
  String get podcast_bulk_delete;

  /// Selected count label
  ///
  /// In en, this message translates to:
  /// **'{count} selected'**
  String podcast_selected_count(int count);

  /// Bulk delete dialog title
  ///
  /// In en, this message translates to:
  /// **'Delete Selected Podcasts'**
  String get podcast_bulk_delete_title;

  /// Bulk delete confirmation message
  ///
  /// In en, this message translates to:
  /// **'Are you sure you want to delete {count} podcast{count, plural, =1{} other{s}}?'**
  String podcast_bulk_delete_message(int count);

  /// Bulk delete warning message
  ///
  /// In en, this message translates to:
  /// **'This action will also delete all episodes associated with these podcasts. This cannot be undone.'**
  String get podcast_bulk_delete_warning;

  /// Bulk delete confirm button
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get podcast_bulk_delete_confirm;

  /// Bulk delete success message
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 podcast} other{{count} podcasts}} deleted successfully'**
  String podcast_bulk_delete_success(int count);

  /// Bulk delete partial success message
  ///
  /// In en, this message translates to:
  /// **'{successCount} deleted, {failedCount} failed'**
  String podcast_bulk_delete_partial_success(int successCount, int failedCount);

  /// Bulk delete failed message
  ///
  /// In en, this message translates to:
  /// **'Delete failed: {error}'**
  String podcast_bulk_delete_failed(String error);

  /// View errors button label
  ///
  /// In en, this message translates to:
  /// **'View Errors'**
  String get podcast_view_errors;

  /// Bulk delete errors dialog title
  ///
  /// In en, this message translates to:
  /// **'Delete Errors'**
  String get podcast_bulk_delete_errors_title;

  /// Dismiss button label
  ///
  /// In en, this message translates to:
  /// **'Dismiss'**
  String get dismiss;

  /// Check for updates button/label
  ///
  /// In en, this message translates to:
  /// **'Check for Updates'**
  String get update_check_updates;

  /// Auto check for updates description
  ///
  /// In en, this message translates to:
  /// **'Automatically check for updates'**
  String get update_auto_check;

  /// New version available title
  ///
  /// In en, this message translates to:
  /// **'New Version Available'**
  String get update_new_version_available;

  /// Skip this version button label
  ///
  /// In en, this message translates to:
  /// **'Skip This Version'**
  String get update_skip_this_version;

  /// Remind me later button label
  ///
  /// In en, this message translates to:
  /// **'Later'**
  String get update_later;

  /// Download update button label
  ///
  /// In en, this message translates to:
  /// **'Download'**
  String get update_download;

  /// Latest version label
  ///
  /// In en, this message translates to:
  /// **'Latest Version'**
  String get update_latest_version;

  /// Published date label
  ///
  /// In en, this message translates to:
  /// **'Published'**
  String get update_published_at;

  /// File size label
  ///
  /// In en, this message translates to:
  /// **'Size'**
  String get update_file_size;

  /// Release notes section label
  ///
  /// In en, this message translates to:
  /// **'Release Notes'**
  String get update_release_notes;

  /// Download failed error message
  ///
  /// In en, this message translates to:
  /// **'Download failed'**
  String get update_download_failed;

  /// Checking for updates message
  ///
  /// In en, this message translates to:
  /// **'Checking for updates...'**
  String get update_checking;

  /// Update check failed title
  ///
  /// In en, this message translates to:
  /// **'Check Failed'**
  String get update_check_failed;

  /// Current version label
  ///
  /// In en, this message translates to:
  /// **'Current Version'**
  String get update_current_version;

  /// Update available description message
  ///
  /// In en, this message translates to:
  /// **'A new version is available. Would you like to update now?'**
  String get update_available_description;

  /// App is up to date message
  ///
  /// In en, this message translates to:
  /// **'You\'re up to date'**
  String get update_up_to_date;

  /// Try again button label
  ///
  /// In en, this message translates to:
  /// **'Try Again'**
  String get update_try_again;

  /// Back button tooltip label
  ///
  /// In en, this message translates to:
  /// **'Back'**
  String get back_button;

  /// Default model badge
  ///
  /// In en, this message translates to:
  /// **'Default'**
  String get ai_model_default;

  /// System model badge
  ///
  /// In en, this message translates to:
  /// **'System'**
  String get ai_model_system;

  /// Enable model tooltip
  ///
  /// In en, this message translates to:
  /// **'Enable model'**
  String get ai_model_enable;

  /// Disable model tooltip
  ///
  /// In en, this message translates to:
  /// **'Disable model'**
  String get ai_model_disable;

  /// Edit config menu item
  ///
  /// In en, this message translates to:
  /// **'Edit Config'**
  String get ai_edit_config;

  /// Test connection menu item
  ///
  /// In en, this message translates to:
  /// **'Test Connection'**
  String get ai_test_connection;

  /// Set as default menu item
  ///
  /// In en, this message translates to:
  /// **'Set as Default'**
  String get ai_set_as_default;

  /// Default test prompt for transcription
  ///
  /// In en, this message translates to:
  /// **'Test audio transcription'**
  String get ai_test_prompt_transcription;

  /// Default test prompt for text generation
  ///
  /// In en, this message translates to:
  /// **'Please briefly introduce AI'**
  String get ai_test_prompt_generation;

  /// Test content validation
  ///
  /// In en, this message translates to:
  /// **'Please enter test content'**
  String get ai_enter_test_content;

  /// Test success message
  ///
  /// In en, this message translates to:
  /// **'Test Successful'**
  String get ai_test_success;

  /// Test failed message
  ///
  /// In en, this message translates to:
  /// **'Test Failed'**
  String get ai_test_failed;

  /// Response speed label
  ///
  /// In en, this message translates to:
  /// **'Response Speed'**
  String get settings_response_speed;

  /// Very fast response
  ///
  /// In en, this message translates to:
  /// **'Very Fast'**
  String get settings_response_very_fast;

  /// Normal response
  ///
  /// In en, this message translates to:
  /// **'Normal'**
  String get settings_response_normal;

  /// Slow response
  ///
  /// In en, this message translates to:
  /// **'Slow'**
  String get settings_response_slow;

  /// Schedule load failed message
  ///
  /// In en, this message translates to:
  /// **'Load Failed'**
  String get schedule_load_failed;

  /// No schedule configuration message
  ///
  /// In en, this message translates to:
  /// **'No configuration found'**
  String get schedule_no_config;

  /// Saving schedule state
  ///
  /// In en, this message translates to:
  /// **'Saving...'**
  String get schedule_saving;

  /// Save settings button
  ///
  /// In en, this message translates to:
  /// **'Save Settings'**
  String get schedule_save_settings;

  /// Current configuration section
  ///
  /// In en, this message translates to:
  /// **'Current Configuration'**
  String get schedule_current_config;

  /// Update frequency label
  ///
  /// In en, this message translates to:
  /// **'Update Frequency'**
  String get schedule_update_frequency;

  /// Update time label
  ///
  /// In en, this message translates to:
  /// **'Update Time'**
  String get schedule_update_time;

  /// Update day label
  ///
  /// In en, this message translates to:
  /// **'Update Day'**
  String get schedule_update_day;

  /// Next update label
  ///
  /// In en, this message translates to:
  /// **'Next Update'**
  String get schedule_next_update;

  /// Hourly frequency option
  ///
  /// In en, this message translates to:
  /// **'Hourly'**
  String get schedule_hourly;

  /// Daily frequency option
  ///
  /// In en, this message translates to:
  /// **'Daily'**
  String get schedule_daily;

  /// Weekly frequency option
  ///
  /// In en, this message translates to:
  /// **'Weekly'**
  String get schedule_weekly;

  /// Schedule settings page title
  ///
  /// In en, this message translates to:
  /// **'Update Settings'**
  String get schedule_settings;

  /// Week short label
  ///
  /// In en, this message translates to:
  /// **'Wk'**
  String get schedule_week_short;

  /// Monday short
  ///
  /// In en, this message translates to:
  /// **'Mon'**
  String get schedule_day_mon;

  /// Tuesday short
  ///
  /// In en, this message translates to:
  /// **'Tue'**
  String get schedule_day_tue;

  /// Wednesday short
  ///
  /// In en, this message translates to:
  /// **'Wed'**
  String get schedule_day_wed;

  /// Thursday short
  ///
  /// In en, this message translates to:
  /// **'Thu'**
  String get schedule_day_thu;

  /// Friday short
  ///
  /// In en, this message translates to:
  /// **'Fri'**
  String get schedule_day_fri;

  /// Saturday short
  ///
  /// In en, this message translates to:
  /// **'Sat'**
  String get schedule_day_sat;

  /// Sunday short
  ///
  /// In en, this message translates to:
  /// **'Sun'**
  String get schedule_day_sun;

  /// Select time placeholder
  ///
  /// In en, this message translates to:
  /// **'Select Time'**
  String get schedule_select_time;

  /// Validation: select time
  ///
  /// In en, this message translates to:
  /// **'Please select update time'**
  String get schedule_select_update_time;

  /// Validation: select time and day
  ///
  /// In en, this message translates to:
  /// **'Please select update time and day'**
  String get schedule_select_time_and_day;

  /// Settings saved message
  ///
  /// In en, this message translates to:
  /// **'Settings saved'**
  String get schedule_settings_saved;

  /// Save failed message
  ///
  /// In en, this message translates to:
  /// **'Save failed'**
  String get schedule_save_failed;

  /// Unknown error message
  ///
  /// In en, this message translates to:
  /// **'Unknown error'**
  String get schedule_unknown_error;

  /// No subscriptions message
  ///
  /// In en, this message translates to:
  /// **'No subscriptions yet'**
  String get feed_no_subscriptions;

  /// Hint to subscribe to podcasts
  ///
  /// In en, this message translates to:
  /// **'Subscribe to podcasts you\'re interested in!'**
  String get feed_no_subscriptions_hint;

  /// Subscribe podcast button
  ///
  /// In en, this message translates to:
  /// **'Subscribe Podcast'**
  String get feed_subscribe_podcast;

  /// Xiaoyuzhou platform name
  ///
  /// In en, this message translates to:
  /// **'Xiaoyuzhou'**
  String get podcast_platform_xiaoyuzhou;

  /// Ximalaya platform name
  ///
  /// In en, this message translates to:
  /// **'Ximalaya'**
  String get podcast_platform_ximalaya;

  /// No show notes message
  ///
  /// In en, this message translates to:
  /// **'No show notes available'**
  String get podcast_no_shownotes;

  /// Unknown error message
  ///
  /// In en, this message translates to:
  /// **'Unknown error'**
  String get podcast_unknown_error;

  /// No search match message
  ///
  /// In en, this message translates to:
  /// **'No matching content found'**
  String get podcast_no_match_found;

  /// No transcript message
  ///
  /// In en, this message translates to:
  /// **'No transcript available'**
  String get podcast_no_transcript;

  /// Click to transcribe hint
  ///
  /// In en, this message translates to:
  /// **'Click \"Start Transcription\" to generate transcript'**
  String get podcast_click_to_transcribe;

  /// Conversation tab label
  ///
  /// In en, this message translates to:
  /// **'Conversation'**
  String get podcast_conversation;

  /// Transcription waiting status
  ///
  /// In en, this message translates to:
  /// **'Waiting to start'**
  String get podcast_transcription_waiting;

  /// Transcription completed status
  ///
  /// In en, this message translates to:
  /// **'Completed'**
  String get podcast_transcription_completed;

  /// Transcription failed status
  ///
  /// In en, this message translates to:
  /// **'Failed'**
  String get podcast_transcription_failed;

  /// Unknown transcription status
  ///
  /// In en, this message translates to:
  /// **'Unknown status'**
  String get podcast_unknown_status;

  /// Date format pattern
  ///
  /// In en, this message translates to:
  /// **'{year}-{month}-{day}'**
  String date_format(int year, String month, String day);

  /// Search input placeholder for podcasts
  ///
  /// In en, this message translates to:
  /// **'Search podcasts...'**
  String get podcast_search_hint;

  /// Country selector label
  ///
  /// In en, this message translates to:
  /// **'Country'**
  String get podcast_country_label;

  /// Empty search state hint message
  ///
  /// In en, this message translates to:
  /// **'Enter a podcast name to search'**
  String get podcast_search_empty_hint;

  /// Search loading message
  ///
  /// In en, this message translates to:
  /// **'Searching...'**
  String get podcast_search_loading;

  /// Search error title
  ///
  /// In en, this message translates to:
  /// **'Search failed'**
  String get podcast_search_error;

  /// No search results message
  ///
  /// In en, this message translates to:
  /// **'No podcasts found'**
  String get podcast_search_no_results;

  /// Subscribe button label
  ///
  /// In en, this message translates to:
  /// **'Subscribe'**
  String get podcast_subscribe;

  /// Subscribed status label
  ///
  /// In en, this message translates to:
  /// **'Subscribed'**
  String get podcast_subscribed;

  /// Subscribe success message
  ///
  /// In en, this message translates to:
  /// **'Subscribed to {podcastName}'**
  String podcast_subscribe_success(String podcastName);

  /// Subscribe failed message
  ///
  /// In en, this message translates to:
  /// **'Failed to subscribe: {error}'**
  String podcast_subscribe_failed(String error);

  /// Hint about network restrictions and VPN
  ///
  /// In en, this message translates to:
  /// **'Network access to iTunes API may be restricted in some regions. Try using a VPN if connection fails.'**
  String get podcast_network_hint;

  /// VPN required message for iTunes API access
  ///
  /// In en, this message translates to:
  /// **'Connection failed. iTunes API may be blocked in your region. Please try using a VPN.'**
  String get podcast_vpn_required;

  /// Country name: China
  ///
  /// In en, this message translates to:
  /// **'China'**
  String get podcast_country_china;

  /// Country name: USA
  ///
  /// In en, this message translates to:
  /// **'USA'**
  String get podcast_country_usa;
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en', 'zh'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'zh':
      return AppLocalizationsZh();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
