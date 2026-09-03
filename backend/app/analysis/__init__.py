"""
app/analysis/ -- offline batch analysis of uploaded log files.

This is the paid-tier "Log Analysis Report" feature. A user uploads a
log file (plaintext, JSON-lines, or CSV); the engine parses each line
through the same normalizer the live ingestion uses, evaluates every
detection rule against the resulting event stream, and produces a
Report the console can render and export as HTML/PDF.

Design:
  * engine.py  -- runs the analysis pipeline
  * report.py  -- turns the raw results into a structured Report + HTML
  * Both operate on data in memory only; no uploaded event ever lands
    in the live `logs` table (so analyzing a customer's own logs
    cannot contaminate the SIEM's own operational data set).
"""
