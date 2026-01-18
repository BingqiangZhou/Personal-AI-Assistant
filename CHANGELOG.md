# Changelog

All notable changes to this project will be documented in this file.



## [0.1.9](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.8...v0.1.9) - 2026-01-18 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.9))

### Ci

- *(release)* Optimize build workflow and configurations ([87a456a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/87a456a886f392d3e9f3e64d86d42327bca8d13e))
- *(release)* Add actions write permission and disable cache read-only ([3007f4d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/3007f4de37484e71aeaa35f6a254892e150684c4))
- *(gradle)* Specify build root directory for accurate caching ([52c6edf](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/52c6edf4869b6682ed47dbf82dcd73420526e1fc))

### 🐛 Bug Fixes

- *(deps)* Move flutter_native_splash to dependencies ([a6a706d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a6a706d8f86f60bcf208ba3f261b5b503f5b15bd))
- *(release)* Fix awk regexp syntax in changelog extraction ([35b6e3c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/35b6e3cdf916006aee05bba73bab91f6fb51e214))
- *(release)* Use prefix match to find version in CHANGELOG.md ([31481fa](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/31481fa0afb43495424d74471907c5e057be3019))
- *(release)* Add consistent header and version info to changelog ([5dfc340](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5dfc340f353f2b1253822c179c492154f84df68e))
- *(changelog)* Skip all version update commits in git-cliff ([d197b56](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d197b566333b7bae9392b8fff1bfc73e4890d0d2))

### 📚 Documentation

- *(release)* Add release command documentation and git-cliff config ([fe5acb1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/fe5acb1e1d3d13118708039a0436c9c323ab65ab))

### 🚀 Features

- *(auth)* Implement auth event system and fix token handling ([d05bff0](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d05bff07b7650f5ab421e6c6c4fa45c94f4f1c1e))
- *(auth)* Improve error handling and message display in auth flow ([44bc937](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/44bc9379f58ef0c28a03ddbf4130e3a0f0ed2bc5))

### 🚜 Refactor

- *(admin)* Move csrf exception handler to dedicated module ([5a568d2](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5a568d2a1afe36fec43d46fc02c5ce1617b8f55d))
- *(release)* Improve changelog generation and template ([2bcc3bf](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2bcc3bf48e92218d5e5729f58f1a34184801bafd))



## [0.1.8](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.7...v0.1.8) - 2026-01-17 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.8))

### ⚙️ Miscellaneous Tasks

- *(version)* Bump version to 0.1.8+21 ([fd50b90](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/fd50b90460bcb8ae288d68998a0caf2718f3ffe0))

### 🐛 Bug Fixes

- *(main)* Comment out security headers middleware for XSS protection ([d17ece5](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d17ece512db3c62dc915c0bbab9cfd8a9ecc0a77))

### 🚀 Features

- *(ai)* Add thinking content filter for AI model responses ([43b55ab](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/43b55ab3ab5b5c016e25203cbd4198f2935e53d9))
- *(podcast)* Enhance transcription and summary services with retry and stats ([f4477a1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f4477a10d15b1ac7056d5c18b328448a7f0a7c37))
- *(ai)* Filter thinking tags from AI responses ([c1bf4af](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c1bf4af933b6946e774b4afc9070d0fdf45d6583))
- *(subscription)* Add latest item published timestamp tracking ([edb9395](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/edb9395be1a71cdc87a940f638be48a2ef861724))
- *(auth)* Implement sliding session and security enhancements ([55eba96](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/55eba965d8f9a5a73603823e73ae4acee49c99e5))
- *(podcast)* Enhance summary generation prompt for improved readability and structure ([59b1426](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/59b1426f4e00645f1a8b13a5e5b1e062357b335b))



## [0.1.7](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.6...v0.1.7) - 2026-01-17 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.7))

### 🐛 Bug Fixes

- *(db)* Add cascade delete to podcast foreign keys ([f6b1626](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f6b162649b97961498f907049bee7c9ea934fce3))
- *(podcast)* Ensure proper deletion order for subscription data ([a6c06d6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a6c06d6c1feeff16025169086bcf20aba43263d9))
- *(admin)* Handle podcast subscription deletion with proper data cleanup ([a79b050](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a79b050b5b8efa58ddb3b51cf818d7be9ac3bd43))
- *(apikeys)* Improve form validation and field consistency ([5156b03](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5156b031f3345d6f5fcbf921ad517091b3acf4b6))
- *(dio_client)* Enhance token retry logic and error handling ([12b0b30](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/12b0b30bc636fb2c856145b0edcc00cf0970519e))

### 📚 Documentation

- Update readme with detailed feature descriptions and architecture ([dd7f623](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/dd7f623b9918092ba219fb4714b565b1d50302c4))

### 🚀 Features

- *(subscription)* Enhance duplicate detection with title and URL matching ([1fbe87a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1fbe87a5d2dde93a2759d5112919893baa0f4d7b))
- *(subscription)* Add OPML export for RSS subscriptions ([736d5ae](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/736d5aefe1a50f2d9c9969bf05f60bcd2f4a51d2))

### 🚜 Refactor

- *(podcast)* Improve subscription deletion with atomic transaction ([bc35637](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/bc3563785c53f9d3e27880c8692d42c491538fcf))
- *(subscription)* Improve podcast subscription deletion flow ([ddbd504](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ddbd504d0a1b4972a9a67010ba6feb06978fa438))
- *(network)* Simplify request retry logic using copyWith ([dd42aee](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/dd42aee3a19269b7efc4b29aa4d2c1681be4c3b4))



## [0.1.6](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.5...v0.1.6) - 2026-01-13 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.6))

### 🐛 Bug Fixes

- *(auth)* Improve JWT token handling in logging middleware ([7143c68](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7143c681d2160553dcbbaee2734b0962e6e5b7e0))
- Remove redundant guid field from subscription response ([3beac2d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/3beac2d4501891dc06ba16702f15a10d91b26401))
- *(podcast)* Handle duplicate episodes in database migration ([08f3ee4](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/08f3ee43132bbbdd02fcb46070995050943a327b))
- *(database)* Handle transcription tasks when removing duplicate episodes ([25e3f85](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/25e3f850dd824ea1c3af7a0823fa225d7727d563))
- *(podcast)* Handle async context in celery tasks and improve db session management ([dd288dd](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/dd288ddf9b38e4e77fb524351ae428f8afe5ac8f))

### 🚀 Features

- Implement auto cache cleanup feature in admin settings ([b869828](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/b869828c1a2a6f3fa2f1d53c2f5f889825e47fc8))
- Update storage cleanup service to remove timezone info from updated_at and enhance manual cleanup button layout ([36fcc50](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/36fcc50f84919d2764e85cc0dd684e97e0f36171))
- Ensure last_fetched_at is treated as an aware datetime for accurate scheduling ([3c6caf3](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/3c6caf3a6e91d665bfbcce848d145dc0bc64ac4e))
- *(logging)* Add admin session authentication to logging middleware ([a6f3fb5](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a6f3fb5e102aa000fac18f2a688eeb75e91ba4b3))
- *(subscriptions)* Add bulk reparse functionality for RSS feeds ([28a70d9](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/28a70d967bc045f405d8e18d1a84b2143f62a9d8))
- *(podcast)* Add scroll-to-top functionality to all tabs ([0d88452](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/0d88452945ae4cd21fdc76e5105fe0b0b8210646))

### 🚜 Refactor

- *(podcast)* Implement model priority-based fallback mechanism ([fbdbbce](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/fbdbbce96dd2804c81cb9a7055c5d61847622c76))
- *(logging_middleware)* Move imports to module level for better readability ([43cd5b8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/43cd5b8d450bd41ff0f622c6cb77489562195608))
- *(podcast)* Replace guid with item_link as unique identifier ([a259522](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a2595221eb541185e17be032cc29479325efbd88))
- *(database)* Remove duplicate podcast episodes before setting unique constraint ([45907ed](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/45907ed523fbb439575ad410f5bd323a090e7ae5))



## [0.1.5](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.4...v0.1.5) - 2026-01-13 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.5))

### 🚀 Features

- Enhance episode description handling by adding HTML stripping and fallback mechanisms ([a5ea9f4](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a5ea9f468839ba6405e623fe52356a884a93d92d))
- Implement podcast feed URL normalization and enhance subscription state management ([2e97885](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2e97885cd5ce2218028b5f22751424a6a525e037))
- Improve loading and status display in podcast episode and transcription widgets with responsive design ([ed31338](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ed31338ccd6faecb334b08a6b03571d07b1792ce))



## [0.1.4](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.3...v0.1.4) - 2026-01-12 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.4))

### 🚀 Features

- *(admin-panel)* Implement user management interface and two-factor authentication utilities ([ac51d80](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ac51d80cb8886acd8a0079aaa5f92381eed58ca0))
- Add system settings page for audio processing configuration and update subscriptions management with frequency settings ([f218138](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f2181382b4485ddae59123cd4aca068a932c4f12))
- Add RSS feed URL testing functionality and error handling in admin panel ([e152933](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e152933cee52dfabd0ccca383d83bcb124d4e9cd))
- Enhance RSS feed URL testing with improved error handling and add API key testing functionality in admin panel ([79ddee8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/79ddee852abe08e20036774478c52d576d7b1fa4))
- *(monitoring)* Implement system monitoring service with detailed metrics collection ([a5c430a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a5c430a0d4a0865a217c3776a82abf1e21b374a0))
- Add database migration step in entrypoint script and configure RUN_MIGRATIONS in docker-compose ([32b9859](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/32b98595d9f1d8819fadc2828db309c368775a3a))
- Update upgrade function to safely drop indexes and table in admin audit log migration ([52c9bd8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/52c9bd8fcc27aaa6c3a5f2274436dae62b592402))
- Refactor upgrade function to safely drop indexes and table in admin audit log migration ([07a62e3](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/07a62e396cdfa440d4ae595c47064c7f01aaa82b))
- Enhance system settings table migration to check for existing table and indexes before creation ([206e8b5](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/206e8b5ac855315e6e26013de1869ff5d88de143))
- Remove automatic migration execution from Docker Compose configuration ([35d703f](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/35d703facac571aeea95f5b05c48fef464f1c1fe))
- Add admin panel 2FA toggle configuration ([e0eb119](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e0eb11971ea8b28242eb93c65004985df34994d3))
- Update User-Agent strings for improved compatibility and testing ([b35367d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/b35367d1f752167fcfcf5817c8f81136b24b2b42))
- Add search functionality to RSS subscriptions management page and enhance connection timeout settings ([fca7027](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/fca702746a49d8c368d53eeb170305b5d083becf))



## [0.1.3](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.2...v0.1.3) - 2026-01-10 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.3))

### 🚀 Features

- Add localization for podcast transcript search and results ([30330cb](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/30330cb698c4d194e53df869fb059d0526f1b1de))
- Enhance podcast feed refresh and transcription task handling with independent database engines ([ae253ab](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ae253ab9a8ad0fd14ec4fb5ba7abb02d3f63d247))
- Increase maximum podcast subscriptions limit to unlimited; enhance bulk import dialog with URL validation and OPML support ([1b019f9](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1b019f99dee18dd83b836402dde3ba669e878a13))
- Enhance podcast RSS parsing and UI for bulk import ([3f3d9ca](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/3f3d9cad4fb9cb80aa3932035f5a55837b7e3bce))
- Change Celery worker hook from worker_ready to worker_init for API configuration validation ([23eaf60](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/23eaf604b87f40cd408541c8e965fbd96c4a2d59))
- Update Celery worker hook to validate API configuration on worker initialization ([ef3a22f](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ef3a22f1e8bdb16a42358d414758036ac02cc4e8))
- Increase maximum RSS size to support very large podcast feeds; update localization for transcription test messages ([2d5f4e4](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2d5f4e43ed47502b7c45e7067263f27111037643))
- Enhance model validation in worker hook to fallback on active models if default is not set ([c5146a9](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c5146a97e3f699f0e5b43104e289e8b59edea01b))
- Enhance API key retrieval with validation and fallback for podcast models ([a78789c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a78789cfd17d7602091fe69cc5750a1cb3c5059d))



## [0.1.2](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.1...v0.1.2) - 2026-01-10 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.2))

### ⚙️ Miscellaneous Tasks

- *(release)* Bump version to v0.1.2 ([f5b9693](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f5b9693d319b4823ec57c644065d9c91e8d18046))

### 🚀 Features

- Add shownotes copy functionality and implement sticky tab bar for improved user experience ([857ce50](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/857ce50b7cc757ec530fdc5c9aea761508553297))



## [0.1.1](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.1.0...v0.1.1) - 2026-01-08 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.1))

### 🚀 Features

- Implement transcription task deletion and cleanup of Redis locks; enhance error handling and logging ([8e16f5e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/8e16f5ebf75dba9804d1fd5fc19cf6d62d6797cb))

### 🚜 Refactor

- Update logging levels for improved clarity and reduced noise in podcast services ([a792f0a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a792f0ac12343bc352c7555212ce348c6445b182))



## [0.1.0](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.9...v0.1.0) - 2026-01-08 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.1.0))

### 🚀 Features

- Rename application to "Stella" and update related metadata; enhance splash screen and localization ([8e6887b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/8e6887ba69077fcc4c40b62d4cbe4b3a3938b598))



## [0.0.9](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.8...v0.0.9) - 2026-01-07 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.9))

### 🚀 Features

- *(build)* Update signing configuration for debug builds to use release signing if available ([31341e0](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/31341e0720d0af61cc265505807b6a76bce3324e))
- *(audio)* Refactor PodcastAudioHandler to use just_audio's automatic interruption handling and manage audio focus manually ([5ca7e87](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5ca7e87f57816c6a5126b37a4c42ec4977002176))
- Refactor audio handling for cross-platform compatibility ([edc67aa](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/edc67aacaafd97ef9ca3594daeec86060d518644))



## [0.0.8](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.7...v0.0.8) - 2026-01-07 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.8))

### 🚀 Features

- Adjust header padding to align with device's top safe area ([1c98fc1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1c98fc1f04f49799afb45db610cbbcd0b982204d))
- *(audio-player)* Completed migration of the audio player to `just_audio` and `audio_service`, fixed Android system media controls, and implemented state synchronization ([2ac2d26](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2ac2d261505a337440217113b222817cf1900483))
- *(audio-handler)* Optimize PodcastAudioHandler for Android 15 + Vivo OriginOS with manual audio focus management and improved state synchronization ([eb365d0](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/eb365d05fcd43c715731478fbdbd5ddd6a90eea8))
- *(side-floating-player)* Enhance draggable functionality and position snapping for the floating player ([d16ede8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d16ede866317f09807c3a54b7fc898e63a4df31f))
- Implement Speed Ruler Control with comprehensive widget tests and documentation ([5fe4e32](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5fe4e32000199d36d744663dd83cb2d8ddf05732))
- Add localization support for podcast features ([87959f4](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/87959f4980bb04a9ee09f198ae59d831707bf87c))
- *(theme)* Implement theme mode management with localization support ([9d341a1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/9d341a1333bee2518bff6344e3ae1feccddc7071))
- *(update)* Implement background APK download service with installation support ([b38d06d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/b38d06df42cf8f760f969f1fbe2ac02d2e7c1c58))



## [0.0.7](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.6...v0.0.7) - 2026-01-04 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.7))

### 🚀 Features

- Adjust header padding to account for top safe area in podcast episode detail page ([befdf16](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/befdf16f5f85cfffc9327fb4c04855cb22796081))
- Update localization strings for podcast summaries and play buttons ([27956cf](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/27956cf09a806a4522dbe01b0e9e59ddd7442a8b))
- Implement episode description display optimization using AI summaries and HTML cleaning ([5520d6e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5520d6e0e0922f1768702085762c4c96d7f68445))
- Remove debug logging for episode database commit confirmation ([c51a0c5](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c51a0c536e6f3a0811e348d6bde8851f7685e1c6))



## [0.0.6](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.5...v0.0.6) - 2026-01-03 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.6))

### 🐛 Bug Fixes

- Correct down_revision identifiers in migration scripts ([e633226](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e6332267ec41aff5024590d5cc23c7a166f3c857))
- Use explicit logger access to avoid scoping issues in error handling ([fcde8b8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/fcde8b8d970670f8c1045de89944cab502abc074))

### 🚀 Features

- Update API key retrieval to read uniformly from the database and enhance User-Agent header for CDN bypass ([0580a63](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/0580a63abaf8ff35803970cec58c75aaaf55cbcf))
- Add logging for HTTP request URL and headers in AudioDownloader ([994e2f3](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/994e2f308f3aa9bf500921d5147beab6c2f0d8d9))
- Enhance logging in AudioDownloader and simplify PodcastSearchResultCard layout ([eeaf2d1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/eeaf2d1ef61f839f3bdc6183a6effed57227cf5d))
- Adjust country selector overlay positioning and width based on search bar dimensions ([994e6ed](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/994e6ed7f5e03e6a4decdd7e6406a5cc966004b7))
- Add product verification report for podcast audio download fallback implementation ([f148391](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f1483913c2b0bf9f3051ffae0ef026247e9fb864))
- Remove ai_model_configs table migration script ([07f9fec](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/07f9fec39f668c5919a80d350989af4c63253f32))
- Enhance browser fallback logic by checking Playwright availability ([57ad7ee](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/57ad7eea2b6aa62340866c464b565733f08cf01a))
- Enhance audio download process by implementing fetch API in browser context ([bb67418](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/bb6741825321e4379e98aa89b58daa0428d6cf56))
- Update Dockerfile for Playwright browser path and install dependencies; refactor audio fetch script to use IIFE ([f3704ea](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f3704ea3504d45052b194c3e13736591ef8a7c6c))
- Refactor BrowserAudioDownloader to use context.request.get() for HTTP requests ([6443582](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/644358234199d074e200679f4ddcc20173bd922d))
- Enhance error logging for BrowserAudioDownloader with detailed 403 response information ([ec9ba75](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ec9ba7522d0919a9a131c74db77572e4a1f180b6))
- Remove browser fallback mechanism from AudioDownloader; switch to direct aiohttp downloads ([051b8fa](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/051b8fab83a3e4d378e5559fc03bb77de206e0a7))
- Enhance AudioDownloader to handle lizhi.fm CDN URLs and add Referer header ([dc30e09](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/dc30e09e941dc1a63e76c4d96845ba2eb6b5823c))
- Add item link functionality to podcast episodes, including backend support and frontend integration ([4f672ee](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/4f672ee83c7cf2d6640aa126cfe90b8132a82d44))
- Add item_link column and index to podcast_episodes table with existence checks ([cdcdf2c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/cdcdf2c94d397d61840cd4bd30fbb60eb0abf990))
- Add download_method column to transcription_tasks with default and constraints ([d540bd1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d540bd12b0cc62cf0c38bf1079ad9474a1d1fad9))
- Remove download_method column from transcription_tasks and associated constraints ([27c453e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/27c453ec62e9842c1eac993e2a15d02b67889251))
- Add reparse functionality for podcast episodes with localization support ([60d9add](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/60d9adde48cb548e3e3d9727fb9f3eb043ea57ee))
- Enhance logging for item link processing in podcast RSS parser ([2abdb0b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2abdb0b62978c6349c600d0e32082566f471b2ca))
- Add logging setup to PodcastRepository for improved debugging ([7b7f49e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7b7f49ebe8b3d59c8757f64b23dff89d4787ed3d))
- Add item link to podcast episode details for improved accessibility ([25aa140](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/25aa140b996cd5c3e7ad8e4c1f58ba2438674204))
- Implement floating podcast player with collapsed and expanded states ([9b348b8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/9b348b8ee29fbe66f4ab1055c303a586fbc8eafb))
- Enhance audio player functionality with close button and clear current episode option ([2373b2d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2373b2d50f54a2a201a4e5be075d9f555374c7af))
- Improve layout responsiveness of expanded podcast player content ([2f76395](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2f76395ed6837ea79d8e4674f7b23e50fb95e1cf))



## [0.0.5](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.4...v0.0.5) - 2026-01-02 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.5))

### 🚀 Features

- *(logging)* Enhance batch logging for PII detection; increase log frequency and add initial log info ([d826747](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d826747ffd92f792875158fba2fb58fa431e7c35))
- Update .gitignore to exclude docker storage; modify Dockerfile for improved package source configuration; enhance summary_manager and transcription service with better logging and progress handling ([0ee33d5](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/0ee33d53147349889e4ca1d71f755779e6ba3d86))
- Add podcast search task tracking and subscription status indicator specifications ([624ffba](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/624ffba641807170756944a25a722f620f85e5ae))
- Enhance podcast subscription status indicator with Material 3 icons and improved UI ([064f8d6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/064f8d61a9d95a6513c5a554addf9d5869c19208))
- *(localization)* Add unknown author label and country names for podcasts ([d46c58b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d46c58bb56b1c312104d594b3a16a7cfec272c83))
- Refactor DioClient to initialize baseUrl synchronously and enhance server URL loading in main ([1979eb0](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1979eb04f7f1b758fadf0f1760bde7c58ad79689))
- Add missing transcript_content field to PodcastTranscriptionResponse and update core providers for baseUrl invalidation ([330733b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/330733be810628f5dfbf82025704b3b98b04bdd7))
- Enhance country selection with a dropdown menu and integrate popular regions in PodcastCountry enum ([e657f8d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e657f8d14007e09c1a8e351cb931d02f0aa5f491))



## [0.0.4](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.3...v0.0.4) - 2025-12-31 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.4))

### ⚙️ Miscellaneous Tasks

- Bump version to 0.0.4+1 in pubspec.yaml ([169df32](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/169df329d2184e7cdc0997296fec783bbd5a6d23))

### 🚀 Features

- Enhance release date formatting in changelog; add timezone support and improve UI for update dialog actions ([0e68254](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/0e682544e10487c7cc23441875d65d38cb7cf3ce))
- *(localization)* Update Chinese localization strings and improve usage across the app ([426049c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/426049cc45180caa82351410ab1af76fa31b77d8))



## [0.0.3](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.2...v0.0.3) - 2025-12-30 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.3))

### 🚀 Features

- Display app version on profile page and update version to 0.0.2+4 ([39d9d64](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/39d9d64aa079a9ef3425fa9b9d9694eedd4e7cfa))
- Implement robust RSS/Atom feed parser with enhanced error handling and data normalization ([fb1fbe6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/fb1fbe68f24df6a67fdb482b2108eb036a12456b))
- Enhance server address settings functionality ([ec53e2f](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ec53e2fb17633a026f41f2ce71b8c2612d5cff61))
- Update Java and Kotlin compatibility to version 21, enhance UI responsiveness and button styles in settings and server config dialogs ([bd5d823](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/bd5d8237d837082a494ea48dcbf59199b31bd96f))
- Enhance episode data structure with image URL and transcript content fallback ([670cf2d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/670cf2dd99426b8f88d8d0ac460657eb0d100757))
- Enhance error handling and logging in DioClient and podcast providers; improve episode loading logic ([c2d1c67](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c2d1c67709e7ba34c2624672c94d02df4c890a7f))
- Implement batch logging for PII detection and progress updates; reduce log frequency in transcription service ([bdab714](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/bdab714b64af56dbc55ab836a5795f5099cfbe77))



## [0.0.2](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.1...v0.0.2) - 2025-12-30 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.2))

### 🐛 Bug Fixes

- *(android)* Resolve Gradle build errors - add Properties import and migrate to new Kotlin DSL ([abc3f6a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/abc3f6abba0b742929ca98933a4b79cc055d5e45))
- *(ci)* Add flutter clean step to Windows build for fresh compilation ([5575f71](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5575f710a6d196dc87b75dd3f8116c32cb026fb9))
- *(i18n)* Add missing update_* localization keys to .arb templates ([915facd](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/915facdfb4b923490ab00719bb5e6e604b44e238))
- Update version number to 0.0.2+2 and add ProGuard rules for Woodstox and StAX ([41d9375](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/41d9375d9de34c2b2f478cc0c064055fc6d0812b))

### 🚀 Features

- Add app update notification feature with task tracking documentation ([adc7604](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/adc76041aad33f6a5aa85876f37a710f7a78f115))
- Update release workflow to use new keystore secrets and add documentation for generating release.keystore ([bd4330c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/bd4330c60cdf91159786d620207f4e6e1f740bf6))
- Add XML StAX API dependency and ProGuard rules for XML parsing ([00ffedb](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/00ffedb128b173c880ff8fbcda4bb61cad904c82))
- Update app version to 0.0.2+3, enhance version retrieval, and improve settings UI with update check functionality ([ec1ded8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ec1ded804c7a83cc075a2884bf82fdade54ec824))



## [0.0.1](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.1-rc...v0.0.1) - 2025-12-29 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.1))

### 🐛 Bug Fixes

- Revert version number to 0.0.1+1 in pubspec.yaml ([97e3e8b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/97e3e8b49ddee19cd40e3c29f14a07f5ef801eb4))
- *(ios)* Use debug mode for iOS simulator build ([5d4dce3](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5d4dce34fc0f7d0db9c59ac3b9b211e36c781857))
- *(ios)* Build iOS device with --no-codesign instead of simulator ([254ce09](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/254ce095313ce9e5333a7117cbad01037c55c141))
- *(ios)* Fix zip command path error in IPA packaging ([bd87ec2](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/bd87ec237336a992a9dcc4dbf5643f6efb8078dd))
- *(theme)* Adjust font sizes and spacing for improved readability across podcast pages ([0f0405f](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/0f0405f21ab10e16a886c04eca46dd3d543af10f))

### 🚀 Features

- Implement floating player control for podcast playback ([d55c91d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d55c91d3899af2ac59623dfa4b536d05605f0d75))
- Add iOS Simulator build job to release workflow ([01a3c51](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/01a3c51bd7d4192528bbd6b795183b49e8111933))
- Add podcast subscription bulk delete feature specification ([73a487a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/73a487a04926a6082ee7586b3784805473ca94fc))
- *(podcast)* Implement lazy loading for podcast subscriptions and optimize button text ([b6a198e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/b6a198e1cc93b11f2768bfeda3b4587820d58ff8))
- *(docs)* Update CLAUDE.md with current feature status and recent major updates ([56bf28d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/56bf28db9a9a5877953c34b7a5e4798a7f62e219))



## [0.0.1-rc](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.1-beta...v0.0.1-rc) - 2025-12-28 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.1-rc))

### 🐛 Bug Fixes

- *(docker)* Update Docker Compose to include env_file for services ([f7452e0](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f7452e03e7414feca6b4327a5fdb6c1af3f70f5d))
- *(android)* Allow cleartext HTTP traffic for remote server connections ([d3ac83c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d3ac83c5e1292d02062e5ac24c5fe4b52fc09679))
- *(android)* Use debug signing for release builds to support overwrite installation ([3806ae8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/3806ae8c6d0c9fd83b908b15fd4dec22c6ab9a38))
- *(android)* Add comprehensive permissions to AndroidManifest ([50d6fa7](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/50d6fa77d8f55c11ad7154b01560eaf9dcad7f4e))

### 🚀 Features

- *(docker)* Update Docker configuration and environment files for improved setup ([c7144b6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c7144b696a9380d577b9bd8e50cbb338db321402))
- *(docker)* Update environment configuration and Docker Compose for improved local development setup ([809e9b6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/809e9b650a624b1a8a763ec2771f0a5063b4454c))
- *(redis)* Update Redis command to conditionally require password based on environment variable ([490242d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/490242d61d8af896c3d10dd798d768be568b29eb))
- *(auth)* Add remember me functionality for login and registration ([ac9425d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ac9425daa4dcbb28209a1858f6b9341a69ea7465))
- *(docker)* Refactor environment configurations for local and production setups ([b747240](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/b747240a205ca712a9e2f22e7f4e8bb08ac29100))
- *(docker)* Update environment configuration for local and production setups ([f5bb302](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f5bb30223f43312b716f4443bb439d723a580c9b))
- *(docker)* Create multiple directories with proper permissions in Dockerfile ([41420e0](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/41420e046e48b23378729053a043526ced394fcf))
- *(api)* Add root endpoint for welcome message and update health check proxy path ([cac92a7](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/cac92a7b8988a6a19633a982a25cd84373f7f5d1))
- *(nginx)* Add HTTPS configuration and auto-configuration script for Nginx ([e81e2e6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e81e2e65c527333c636ca849e909f666aa433057))
- *(docker)* Remove HTTPS configuration files and update Nginx settings for domain configuration ([8c67697](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/8c676970c583befb6646f90859a9059e3cff3c81))
- *(nginx)* Add auto-configuration script and HTTPS template for Nginx ([dadae8b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/dadae8b204374a66b5ebe737b2d59fb1b757ebd4))
- *(nginx)* Update Nginx configuration for auto-configuration script and entrypoint handling ([1aaf61b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1aaf61ba1fee4d6a69a9da5a51e88287cd7b1c2f))
- Implement dynamic server configuration and connection testing ([3b736f8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/3b736f8eb3f027f76b5724fc1b3099f93f104e40))
- *(docker)* Add entrypoint script for permission management and update dependencies ([4234a73](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/4234a73ef36a727229bdcac7d9fa4c40e60d8412))
- *(docker)* Enhance entrypoint script to use setpriv for user execution ([0c4973b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/0c4973b7a453d25d791af0b8230b92124b44439c))
- *(nginx)* Remove default Nginx configuration for development environment ([ba95bda](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ba95bda7f21973dfe2372bcb251c378fbbbd5367))
- *(docker)* Clean up default Nginx configuration files to avoid conflicts ([bdf24fb](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/bdf24fb89e46e34d9c6aa43fe269cc0f66cfbce6))
- Update error logging to include response data and upgrade dependencies ([83c72e1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/83c72e1ebdcaa09ffecab5a4c3bd408157c7c21d))
- Update provider constructors to be constant and adjust build methods ([4edd902](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/4edd902329b0ae44c941aa9007640a73382243c1))



## [0.0.1-beta](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/v0.0.1-alpha...v0.0.1-beta) - 2025-12-27 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.1-beta))

### 🐛 Bug Fixes

- *(ui)* Enhance UI components for better accessibility and usability ([0526127](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/0526127700e1ddad09cd558c734e4410294a0328))

### 🚀 Features

- *(docker)* Add comprehensive Docker setup for production and development environments ([1451d41](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1451d41032f87dd6b0cd075eee4617318e4f6724))
- Add Mindriver theme configuration with light and dark variants ([7c46457](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7c46457e78dd392dc315c1e2092074b9ec07d092))



## [0.0.1-alpha](https://github.com/BingqiangZhou/Personal-AI-Assistant/compare/...v0.0.1-alpha) - 2025-12-27 ([📥](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.0.1-alpha))

### Refactor

- Remove old main files and implement new podcast episode cards ([2187ac0](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2187ac08b9465c05675d595a042e7f5a34d5da50))

### ⚡ Performance

- *(ci)* Optimize Android build speed ([6d31d05](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/6d31d059585b0a9e0334db4c2ccf50f47308b212))
- *(ci)* Improve Android Gradle caching strategy ([668051e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/668051e0e2649e10f3b230fa2f70089453ad6a4f))
- *(ci)* Optimize Windows build workflow ([53a8572](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/53a8572ac822a091d5203473029cadb927406ccd))
- *(ci)* Optimize Linux build workflow ([3f996f1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/3f996f102e01f6404a5609e90e7249229877138e))
- *(ci)* Optimize macOS build workflow ([d885c68](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d885c6875673f69cac41a8d7e24260b28bb1d39c))
- *(ci)* Add pub-cache caching to Android and Windows ([1b32e9d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1b32e9d769368042d4b0487e84013230cf759f35))
- *(ci)* Skip Finder beautification in macOS DMG creation ([9f31a22](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/9f31a22f04972e93be927b84092482bd8265fcef))
- *(ci)* Optimize cache keys and use system tools ([aa1e33a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/aa1e33a2f9ed7fa60cc6a4384bcd207d63b6b04b))

### 🐛 Bug Fixes

- *(release)* Simplify changelog generation and add verification step ([357ad12](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/357ad127f651149edceefb14d94bcf42151da995))
- *(release)* Correct working directories for desktop builds ([ea29b37](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ea29b3743644b1b7c4129b8db91fa88643312170))
- *(ci)* Update Flutter to use latest stable version ([c175eda](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c175edaf1a5aa00b3164c50e40c28d623db5515d))
- *(deps)* Resolve dependency conflicts and update packages ([2b428ec](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2b428ecd49c6d214225fcc37b10b12dbe3c1349c))
- *(ci)* Add gstreamer dependencies for Linux build ([22b6df8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/22b6df8d6e560b50a7bb19e039012621d03a3112))
- *(ci)* Use bash shell for Windows build commands ([dc9cc9f](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/dc9cc9f78b2ab81537a92486a62640dbbd8f256b))
- *(ci)* Build Android APK for arm64 only ([5d48d02](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5d48d024d4eed1849d6e18ddcb153dc169d55718))
- Add placeholder files to empty asset directories ([85eae96](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/85eae96042745d5e287cdbdec66278179b9edfff))
- Remove empty assets declarations from pubspec.yaml ([449a957](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/449a957cbc281ec3e93e89b686a25fe79a3fbe14))
- *(ci)* Add libsecret-1-dev for Linux secure storage ([5c76594](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5c76594d39929d426c86d5fe71d1e4b13fd0a483))
- *(ci)* Add build cache cleanup for Windows build ([cddca5d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/cddca5d0daa32465311a16fea9e33dbee6e94c0a))
- *(ci)* Fix Linux tar archive creation command ([730b658](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/730b6584b5b2251a40770c798ae37f76cd407a25))
- *(ci)* Use bash and zip for Windows archive creation ([7eb9e8e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7eb9e8e084124097ea89bfe570e143e05718f0d4))
- *(deps)* Upgrade audio_service to fix build warnings ([afc26be](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/afc26bea75b5e646a54a062cbbfb69ddcf38a220))
- *(ci)* Correct Windows build output path ([8ef8483](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/8ef8483acd404f7d6bce9be2b470902ea1dcba26))
- *(ci)* Extract numeric build number from version ([6c7fb66](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/6c7fb66368d67bbff201a0b43b1d428b7ea7b4eb))
- *(ci)* Use PowerShell Compress-Archive for Windows ([30cc884](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/30cc884ba96098d4b184617fe9af341d2480d3fc))
- *(backend)* Correct User model attribute in podcast task ([9228f6e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/9228f6e608b7fd8bd234dab3417702153e138743))
- *(ci)* Add bash shell for Windows build step ([9213b57](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/9213b57daa7c6782d174cee3ac4640761d4d4a87))
- *(ci)* Correct macOS archive path ([9c9fe68](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/9c9fe68025e7749e5aff4922799c33707bb64fc6))
- *(ci)* Correct release condition and unify cache keys ([b99ae2b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/b99ae2b4a518f37529a9b854692398de4f446fe5))
- *(ci)* Correct macOS DMG creation path handling ([f3b83a4](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f3b83a4da18d119f1505b93d8ceb2afd60808af5))
- *(deps)* Update flutter_markdown to flutter_markdown_plus and adjust related imports ([0ae64ee](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/0ae64ee0dff3f5e53d6cb40b1530e972aea49ec9))
- *(ui)* Add SafeArea to ResponsiveContainer for mobile to prevent status bar overlap ([7ed316b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7ed316b20ce0af5cc81534d246ebbbd51d2c0b5e))

### 📚 Documentation

- Add CHANGELOG.md for v0.0.1 and update README with bilingual features ([581c5d6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/581c5d6b9368c1b6ee629b4dfeb706fc3deb9bb8))

### 🚀 Features

- Implement comprehensive multi-agent collaboration system with workflows for feature development, bug fixing, and architecture review ([3224cb8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/3224cb897301d571a143ea7749edfc8863b3d95f))
- Enhance database and security modules with production-ready optimizations and health checks ([aeae44a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/aeae44a4ca5e0c885815a8d9c2a7a39caf677fb1))
- *(docker)* Add comprehensive deployment documentation and scripts for podcast feature ([a26422a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a26422a34932d7bc4a125a5d65ec18d39903e29a))
- Add metadata headers to agent documentation files and create devtools options configuration ([e3eaacd](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e3eaacd68242bdc79630a97fb7dabd4b996c92c5))
- Add generated plugin registrant files for Linux and Windows platforms ([be828af](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/be828af4c388c0b9c7460ab023185c7671ce8e67))
- Update Flutter dependencies and configurations for Windows desktop support ([48c70ed](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/48c70edcf4d2c8eb74ec38d0b4025ebee422d54a))
- Update Flutter dependencies and improve plugin registrations for macOS ([1fb9df4](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1fb9df4e00fb5b90665c037d64bee1285a25b16a))
- Enhance Flutter widget testing guidelines and enforce mandatory usage for page functionality ([1efc13e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/1efc13efc07ba8d9105e3cb5717519e1c32dd022))
- Add UI structure validation tests and functional test reports for podcast feature ([c81838e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c81838ef346441944b64454528c5409f8a9f428d))
- Add comprehensive authentication test report and fix login API field mismatch ([da579ba](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/da579ba910516de4d4729b14abd479ed071d51e4))
- Enhance podcast player UI and functionality ([e070c6a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e070c6a8360c34b3ec96bf72e39964aabbdcfc81))
- Implement podcast platform detection and validation ([61f9c47](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/61f9c47cd40e36b3c496f3449bc72fe94e329968))
- Add comprehensive workflow documentation and templates for requirement-driven development ([a2df0cc](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a2df0cc26f863676e2ce7a9bfa6c99696db59859))
- Implement podcast feed feature with lazy loading and error handling ([b62362c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/b62362c7430704b1b36dee425ee5ec686ddd7c21))
- Enhance product-driven development workflow with mandatory actions and validation checks ([2e0b95c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/2e0b95c9e6cb6c49e7a4f27447d2c6c2c077d1f4))
- Add default values for boolean fields in API response models and update podcast feed provider references ([15ab3bc](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/15ab3bcd7188e5fb4dab1e475174135d2a0eda4e))
- Implement podcast feed page optimization and UI translation ([424ea77](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/424ea77c8515cb436a46cf8833fa8227992494d5))
- Complete Material 3 UI refactoring (Phases 1 & 2), refactor all 17 pages, and implement responsive layouts ([4315768](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/43157681a588e313de05f2a0d7d80ad143fcf011))
- Implement podcast audio player enhancements ([71419d6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/71419d6cc787c7a0dff56f6c6cb525039c88854d))
- Add image URL field to podcast episodes and update related models and services ([993de86](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/993de8604833c8b3a91b4dbb12df21021bc3abc9))
- Add adaptive menu components and tests ([dd6d254](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/dd6d254d1e34dfcef563199ee358809c6132bddd))
- Update product-driven development workflow and enhance MCP tools guidance ([4e5a981](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/4e5a98153516eb734dae2d33a6598f4b0a36fe5a))
- Implement podcast transcription feature with shownotes display ([e449e96](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e449e960a62f9aafac3d6a30145bb31c520dfa5f))
- Add model creation, editing, listing, and testing dialogs for AI models ([e7eb07e](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/e7eb07e22b284d3b5830ee1ba5dd24dbdccbff43))
- Implement adaptive navigation and loading page for Material Design 3 ([a1215e6](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a1215e6ac27da33070ea2c9e2732be93fd774553))
- Implement Knowledge Management API and Models ([7bde4c3](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7bde4c376d2af77a7188155a72c337c094c48051))
- Implement Assistant, Subscription, and Multimedia domains ([5e5ae3b](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/5e5ae3b1b6168dcefb812491317f67f519ccf834))
- *(transcription)* Add current_step field to transcription_tasks and enhance transcription state management ([9fd53cd](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/9fd53cdcd317d5569a4a99dbe34655ef47afcdd5))
- *(security)* Implement RSA key management and encryption for API keys ([f9ac2e2](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f9ac2e2387fabee9f983944b30c2d4ff493c7eed))
- Implement AI summary feature for podcast episodes ([97482d8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/97482d8b4248b319e46a7231b1c35519e3972a46))
- *(api)* Add API key validation endpoint and enhance model retrieval with optional decryption ([febe0c2](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/febe0c28cd864038202fce31e3b30a4afe81474e))
- Enhance AI Summary functionality and improve UI components ([cdc2810](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/cdc2810558bb52d3d48f5616555aef0e3faa0196))
- Add podcast conversations table and implement conversation service ([263e748](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/263e748d183358416f6c22f1b002de70771c39ec))
- Integrate flutter_markdown for enhanced summary display and update UI text to English ([846696a](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/846696af1637975dc6d75394664d7932bcd02f42))
- Implement global schedule provider and schedule configuration provider ([7bca8a3](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7bca8a3f4836e3646ba4258037bfe0046ebd3c26))
- Implement bulk podcast subscription feature ([82bcf23](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/82bcf23271df08fb167a6c50792d89dead698bcf))
- Add Celery Beat service and implement subscription checking functionality ([7d4bf33](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7d4bf338948cf54a569be99b3935cce7f673af8d))
- Enhance database connection handling and add test script for SimpleModel ([c4e250c](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c4e250c1503ece5e576cdc22ba5789593c537d6c))
- Refactor subscription update logic and remove obsolete files ([a1a0d08](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/a1a0d08a641c4e6af814b8231ee0a2b87a2f5b9d))
- Revise README to enhance clarity on features and technical architecture ([343b80d](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/343b80ddab473639c336a98ee337c9a5f50f4db3))
- *(logging)* Implement unified logging configuration and middleware ([c76b054](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/c76b054d7dfa7af350afb059bf068f17dfa4f5ef))
- Enhance bilingual support across agents and workflows, including language matching and documentation requirements ([ee5da93](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ee5da93c289ac84d819c9d30edd9cdeaf94accbc))
- *(localization)* Add Chinese translations for backend API settings and UI elements ([ac32db9](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/ac32db912797ac5f97b734e744c46a16a51951b8))
- Add CI and release workflows for multi-platform builds and automated testing ([406a8fc](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/406a8fcb60f17f0935d305d06b53720bebeb0f18))
- Add GitHub Actions quick reference documentation ([d71c3ae](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/d71c3ae031c2e28fd0def67a4bb3129b885abce7))
- *(ci)* Reintroduce CI workflow for backend and frontend with comprehensive testing and coverage ([f43eee8](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f43eee863b28cdad72fa0c220341dd8604aac9ad))
- Add screen retriever and window manager plugins for all platforms ([f13f6a1](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f13f6a14d9b1c71fcf3dec300f1b39763f4e60ef))
- *(ci)* Add flutter config for Windows desktop ([b8d0417](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/b8d0417fe20c1d8036ff6a8f4b3f1cfc02ad76e5))
- *(ci)* Change macOS packaging from ZIP to DMG ([7ef31c9](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/7ef31c986ba713c3e4be3acb16b9b7ac9b6a4d4b))

### 🚜 Refactor

- *(ci)* Optimize release workflow based on best practices ([f29e484](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/f29e4841753b48432f26dfaf2c15c3805646f77d))
- *(ci)* Optimize Android build artifacts ([43d7429](https://github.com/BingqiangZhou/Personal-AI-Assistant/commit/43d7429c60b81250aeeef50df402cb54d2e0691b))

---
*This changelog was automatically generated by [git-cliff](https://github.com/orhun/git-cliff)*
