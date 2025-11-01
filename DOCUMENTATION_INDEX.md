# FalconPy Detection Management - Documentation Index

**Project:** CrowdStrike Falcon Bulk Detection Management
**Created:** 2025-10-31
**Status:** ✅ Production Ready

---

## Quick Start

**New to the project? Start here:**

1. **Setup Guide** → [`SETUP_GUIDE.md`](SETUP_GUIDE.md)
2. **Quick Reference** → [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md)
3. **Try it:** `venv/bin/python scripts/query_detections.py --test-connection`

---

## Documentation Files

### 📚 Core Documentation

#### [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md)
**Quick command reference for daily use**
- Common commands with examples
- FQL filter examples
- Multi-customer workflow
- Troubleshooting quick fixes

**Use this for:** Daily operations, looking up command syntax

---

#### [`SETUP_GUIDE.md`](SETUP_GUIDE.md)
**Complete setup and installation instructions**
- Initial environment setup
- API credential configuration
- Multi-customer setup
- Architecture explanation
- Security best practices

**Use this for:** First-time setup, new deployments, customer onboarding

---

#### [`SCRIPTS_REFERENCE.md`](SCRIPTS_REFERENCE.md)
**Detailed reference for all scripts**
- Complete parameter documentation
- Input/output examples
- Workflow patterns
- Exit codes
- Performance metrics

**Use this for:** Understanding script details, advanced usage

---

#### [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)
**Solutions to common problems**
- Connection issues
- Query/search problems
- Closure/update errors
- Script execution issues
- Diagnostic commands

**Use this for:** When something isn't working

---

#### [`SESSION_NOTES_251031.md`](SESSION_NOTES_251031.md)
**Historical record of project development**
- What we built
- Key discoveries
- Lessons learned
- Technical details
- Testing & validation

**Use this for:** Understanding project history, reference for decisions made

---

### 📁 Project Files

#### [`README.md`](README.md)
**Project overview and basic usage**
- Project structure
- Setup instructions
- Usage examples
- Safety features

---

#### [`.env.example`](.env.example)
**Template for API credentials**
- Copy to `.env` and fill in credentials
- Never commit actual `.env` file!

---

## Scripts Overview

### Analysis & Reporting
| Script | Purpose | Output |
|--------|---------|--------|
| `hash_summary.py` | Analyze SHA256 hashes | Terminal + Markdown file |
| `query_detections.py` | Search detections | Terminal |

### Operations (Modifies Data!)
| Script | Purpose | Safety Features |
|--------|---------|-----------------|
| `close_by_hash.py` | Close by SHA256 | Dry-run, confirmation prompt |
| `bulk_close_detections.py` | Bulk close by filter | Dry-run, confirmation prompt |
| `create_ioc_exclusion.py` | Create hash exclusions | Confirmation prompt |

---

## Quick Command Reference

### Most Common Commands

```bash
# 1. Generate hash report
venv/bin/python scripts/hash_summary.py -o report_$(date +%y%m%d).md

# 2. Search by hash
venv/bin/python scripts/query_detections.py \
  --hash "YOUR_HASH" \
  --details

# 3. Close by hash (dry-run first!)
venv/bin/python scripts/close_by_hash.py \
  --hash "YOUR_HASH" \
  --dry-run

# 4. Close by hash (for real)
venv/bin/python scripts/close_by_hash.py \
  --hash "YOUR_HASH" \
  --comment "Benign - SOC approved"

# 5. Bulk close (ALWAYS dry-run first!)
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --dry-run
```

---

## Documentation by Use Case

### 🆕 I'm setting up for the first time
1. Read: [`SETUP_GUIDE.md`](SETUP_GUIDE.md)
2. Follow: Initial Setup section
3. Test: Connection test command
4. Bookmark: [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md)

### 📊 I want to generate a report
1. Command: `venv/bin/python scripts/hash_summary.py -o report.md`
2. Reference: [`SCRIPTS_REFERENCE.md`](SCRIPTS_REFERENCE.md) → hash_summary.py
3. Examples: [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md) → Daily Commands

### 🔍 I need to find a specific detection
1. Command: `venv/bin/python scripts/query_detections.py --hash "YOUR_HASH"`
2. Reference: [`SCRIPTS_REFERENCE.md`](SCRIPTS_REFERENCE.md) → query_detections.py
3. Filters: [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md) → Common FQL Filters

### ✅ I want to close detections
1. **IMPORTANT:** Always dry-run first!
2. Read: [`SCRIPTS_REFERENCE.md`](SCRIPTS_REFERENCE.md) → close_by_hash.py
3. Follow: Workflow patterns in [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md)
4. Command: `venv/bin/python scripts/close_by_hash.py --hash "HASH" --dry-run`

### 🔧 Something isn't working
1. Read: [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)
2. Run: Diagnostic commands
3. Check: Environment variables and credentials

### 👥 I'm setting up for multiple customers
1. Read: [`SETUP_GUIDE.md`](SETUP_GUIDE.md) → Multi-Customer Setup
2. Follow: [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md) → Multi-Customer Workflow
3. Create: Separate `.env` files per customer

### 📚 I want to understand the code
1. Read: [`SESSION_NOTES_251031.md`](SESSION_NOTES_251031.md) → Technical Details
2. Read: [`SETUP_GUIDE.md`](SETUP_GUIDE.md) → Understanding the Architecture
3. Review: `lib/falcon_utils.py` source code

---

## Key Concepts

### Detection Types
The system handles multiple detection types with different characteristics:

| Type | Product | Hash Field | Description |
|------|---------|------------|-------------|
| XDR | `xdr` | `entities.sha256` | Behavioral detections |
| ODS | `epp` | `sha256` | On-Demand Scans |
| IDP | `idp` | None | Identity Protection |
| EPP | `epp` | `entities.sha256` | IOC matches |

### API Migration
**Important:** CrowdStrike decommissioned the Detects API.
- ❌ **Old:** Detects API → 404 error
- ✅ **New:** Alerts API → Current
- **Note:** GUI still says "Detections" but API is "Alerts"

### Status Values
Valid status values for closing detections:
- `new` - New/unreviewed
- `in_progress` - Under investigation
- `closed` - Resolved (use this for benign)
- `reopened` - Reopened after closure
- ❌ **NOT VALID:** "resolved" (use "closed" instead)

---

## Safety Features

### All Bulk Operations Include:
- ✅ **Dry-run mode** - Preview before making changes
- ✅ **Confirmation prompts** - Prevents accidental execution
- ✅ **Batch processing** - Handles large volumes safely
- ✅ **Rate limiting** - Prevents API throttling
- ✅ **Progress tracking** - Shows what's happening
- ✅ **Error handling** - Graceful failure recovery

### Best Practices:
1. **Always dry-run first**
2. **Start with small batches**
3. **Include meaningful comments**
4. **Review hash summaries before closing**
5. **Test with one hash before bulk operations**

---

## Project Structure

```
falconpy/
├── README.md                    # Project overview
├── QUICK_REFERENCE.md          # Daily commands (⭐ most used)
├── SETUP_GUIDE.md              # Complete setup instructions
├── SCRIPTS_REFERENCE.md        # Script documentation
├── TROUBLESHOOTING.md          # Problem solving
├── SESSION_NOTES_251031.md     # Development history
├── DOCUMENTATION_INDEX.md      # This file
│
├── .env                        # API credentials (secret!)
├── .env.example                # Template
├── .gitignore                  # Protects secrets
├── requirements.txt            # Python dependencies
│
├── lib/
│   └── falcon_utils.py         # Core library
│
├── scripts/
│   ├── hash_summary.py         # Hash analysis
│   ├── query_detections.py     # Search detections
│   ├── close_by_hash.py        # Close by hash
│   ├── bulk_close_detections.py # Bulk operations
│   └── create_ioc_exclusion.py # IOC management
│
├── venv/                       # Virtual environment
│
└── reports/                    # Generated reports (your files)
    ├── cintas_251031.md
    ├── daily_YYMMDD.md
    └── ...
```

---

## Getting Help

### Documentation Not Enough?

1. **Check diagnostics:**
   ```bash
   venv/bin/python scripts/query_detections.py --test-connection
   ```

2. **Review troubleshooting:**
   ```bash
   cat TROUBLESHOOTING.md | grep -A 10 "your error message"
   ```

3. **External resources:**
   - FalconPy Docs: https://falconpy.io/
   - CrowdStrike API: https://falcon.crowdstrike.com/documentation/
   - CrowdStrike Support: https://supportportal.crowdstrike.com/

---

## Maintenance Schedule

### Daily
- Generate hash summary report
- Review and close false positives

### Weekly
- Check for FalconPy updates: `venv/bin/pip list --outdated`
- Review API usage in CrowdStrike console

### Monthly
- Review closed detections accuracy
- Archive old reports
- Update documentation if workflow changes

### Quarterly
- Rotate API credentials
- Review and update API scopes
- Test disaster recovery (redeployment)

---

## Version History

### v1.0 - 2025-10-31 (Initial Release)
**Features:**
- ✅ Alerts API integration (migrated from deprecated Detects API)
- ✅ Hash summary reporting
- ✅ Search by hash (XDR + ODS)
- ✅ Close by hash
- ✅ Bulk operations
- ✅ IOC exclusions
- ✅ Multi-customer support
- ✅ Comprehensive documentation

**Tested:**
- ✅ Connection to CrowdStrike API
- ✅ Query 10,000+ detections
- ✅ Close detections (4 successfully closed)
- ✅ Generate reports
- ✅ Export to markdown

**Known Limitations:**
- Query limit: 10,000 detections (API limitation)
- No pagination implementation yet
- ODS detections remain `show_in_ui: True` when closed

---

## Success Metrics

### Project Goals - All Met! ✅

1. ✅ **Connect to CrowdStrike Falcon API**
   - Successfully authenticated
   - Migrated to current Alerts API

2. ✅ **Query endpoint detections**
   - Query by filter
   - Query by hash (both XDR and ODS)
   - Handle 10,000+ detections

3. ✅ **Identify detections by SHA256 hash**
   - Created hash_summary.py
   - Generates markdown reports
   - Counts and sorts by frequency

4. ✅ **Bulk mark detections as resolved**
   - close_by_hash.py
   - bulk_close_detections.py
   - Safety features (dry-run, confirmations)

5. ✅ **Support multiple customers**
   - Separate .env files
   - Easy switching
   - Multi-customer workflow documented

6. ✅ **Generate reports**
   - Terminal + markdown output
   - Timestamped
   - Ready for sharing

---

## What's Next?

### Potential Enhancements (Future)
- [ ] Pagination for >10k detections
- [ ] CSV/JSON export formats
- [ ] Scheduled reports (cron wrapper)
- [ ] Email notifications
- [ ] Progress bars (tqdm already in requirements)
- [ ] `--env-file` parameter for easier customer switching
- [ ] Web dashboard (optional)

### Not Planned (Out of Scope)
- ❌ GUI application
- ❌ Real-time monitoring
- ❌ Webhook integrations
- ❌ Custom detection rules

---

## Support & Contact

**Project Location:**
`/home/kthompson/Development/Projects/falconpy`

**Primary User:**
Kyle Thompson (kthompson@tachtech.net)

**Documentation Maintained By:**
Claude AI Assistant (Session: 2025-10-31)

**Last Updated:**
2025-10-31 17:31:22

---

## License & Usage

This project uses:
- **FalconPy:** Public Domain (Unlicense)
- **Project Scripts:** Internal use

Credentials and `.env` files are proprietary and confidential.

---

## Acknowledgments

**Built Using:**
- Python 3.x
- FalconPy v1.5.4
- CrowdStrike Falcon Alerts API

**Special Thanks:**
- CrowdStrike for FalconPy SDK
- CrowdStrike Support for API documentation

---

**🎉 Project Complete and Production Ready!**

For questions about this documentation, refer to the individual files listed above.
