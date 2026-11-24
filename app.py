import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import time
import io

DB_FILE = "enterprise_vault.db"

def get_db():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS canary_registry (
            canary_id TEXT PRIMARY KEY,
            issued_to TEXT,
            export_purpose TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

st.set_page_config(page_title="Canary Data Leak Attribution", layout="wide", page_icon="🛡️")
st.title("🛡️ Database Canary & Leak Attribution System")
st.caption("Universal Honeypot Injection & Data Leak Forensics")

tabs = st.tabs(["📊 Database Master (Upload Own Data)", "📤 Export Portal (Watermarking)", "🔍 Leak Forensic Auditor", "📜 Canary Registry"])

# csv file upload madid read madtad
with tabs[0]:
    st.subheader("Master Dataset Management")
    
    upload_master = st.file_uploader("Upload your own custom dataset (CSV)", type=["csv"], key="master_upload")
    conn = get_db()
    
    if upload_master is not None:
        try:
            custom_df = pd.read_csv(upload_master)
            custom_df.to_sql("custom_master_data", conn, if_exists="replace", index=False)
            st.success(f"Successfully loaded '{upload_master.name}' into the secure database ({len(custom_df)} rows).")
        except Exception as e:
            st.error(f"Error loading CSV: {e}")

    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='custom_master_data'")
    table_exists = cur.fetchone() is not None
    
    if table_exists:
        df_display = pd.read_sql("SELECT * FROM custom_master_data", conn)
        st.write("Active Database Table Preview:")
        st.dataframe(df_display, use_container_width=True)
    else:
        st.warning("No custom dataset uploaded yet. Upload your CSV above, or click below to seed sample data.")
        if st.button("Load Default Sample Data"):
            sample_data = pd.DataFrame([
                {"user_id": 101, "name": "Aarav Sharma", "email": "aarav.s@corp.internal", "role": "Developer", "balance": 125000},
                {"user_id": 102, "name": "Priya Nair", "email": "priya.n@corp.internal", "role": "Analyst", "balance": 98000},
                {"user_id": 103, "name": "Rohan Iyer", "email": "rohan.i@corp.internal", "role": "DevOps", "balance": 74000},
                {"user_id": 104, "name": "Ananya Rao", "email": "ananya.r@corp.internal", "role": "Manager", "balance": 82000},
            ])
            sample_data.to_sql("custom_master_data", conn, if_exists="replace", index=False)
            st.rerun()
    conn.close()

# eradnad watermark selection option
with tabs[1]:
    st.subheader("Authorized Data Export")
    st.write("Exports inject a custom or dynamic canary token to trace potential leakage.")
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='custom_master_data'")
    has_data = cur.fetchone() is not None
    
    if not has_data:
        st.error("Please load or upload a dataset in Tab 1 first.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            emp_name = st.text_input("Requesting Employee / Recipient", value="Alice Jenkins (Engineering Lead)")
        with col2:
            export_reason = st.text_input("Export Justification", value="Quarterly Compliance Review")

        # custom watermark select madak kodtad
        watermark_mode = st.radio("Watermark Generation Method:", ["Auto-Generated Secure Hash", "Custom Defined Watermark Tag"], horizontal=True)
        
        custom_tag_input = ""
        if watermark_mode == "Custom Defined Watermark Tag":
            custom_tag_input = st.text_input("Enter Your Custom Watermark Tag:", placeholder="e.g., AUDIT_2026_XYZ or VIP_LEAK_TOKEN").strip().upper()

        if st.button("Generate & Watermark Export", type="primary"):
            export_time = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # yavd watermark use madbek decide madtad
            if watermark_mode == "Custom Defined Watermark Tag" and custom_tag_input:
                canary_hash = custom_tag_input
            else:
                raw_key = f"{emp_name}_{export_reason}_{time.time()}"
                canary_hash = hashlib.sha256(raw_key.encode()).hexdigest()[:8].upper()
            
            # database entry kodtad
            cur.execute(
                "INSERT OR REPLACE INTO canary_registry (canary_id, issued_to, export_purpose, timestamp) VALUES (?, ?, ?, ?)",
                (canary_hash, emp_name, export_reason, export_time)
            )
            conn.commit()
            
            #Current table read madtad
            base_df = pd.read_sql("SELECT * FROM custom_master_data", conn)
            
            #Rows columns g watermark jote match madtad
            canary_row = {}
            for col in base_df.columns:
                col_lower = col.lower()
                if "id" in col_lower:
                    canary_row[col] = 99999
                elif "email" in col_lower:
                    canary_row[col] = f"canary.{canary_hash.lower()}@token-audit.internal"
                elif "name" in col_lower:
                    canary_row[col] = f"Canary Record [{canary_hash}]"
                elif pd.api.types.is_numeric_dtype(base_df[col]):
                    canary_row[col] = 0
                else:
                    canary_row[col] = f"MARKER-{canary_hash}"
            
            if not any("email" in c.lower() or "name" in c.lower() for c in base_df.columns):
                first_col = base_df.columns[0]
                canary_row[first_col] = f"CANARY-{canary_hash}"
            
            final_export = pd.concat([base_df, pd.DataFrame([canary_row])], ignore_index=True)
            csv_bytes = final_export.to_csv(index=False).encode('utf-8')
            
            st.success(f"Export ready! Injected Watermark Token: **`{canary_hash}`**")
            st.download_button(
                label="⬇️ Download Watermarked Dataset (CSV)",
                data=csv_bytes,
                file_name=f"export_{canary_hash.lower()}.csv",
                mime="text/csv"
            )
    conn.close()

# murane tab data breach aged o ello nodtad
with tabs[2]:
    st.subheader("Forensic Leak Attribution")
    st.write("Upload any suspected leak dump to scan for registered canary markers.")
    
    uploaded_leak = st.file_uploader("Upload Suspect / Leaked CSV", type=["csv"], key="leak_upload")
    
    if uploaded_leak is not None:
        try:
            leak_df = pd.read_csv(uploaded_leak)
            st.write("Uploaded File Preview:")
            st.dataframe(leak_df.head(5), use_container_width=True)
            
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT canary_id FROM canary_registry")
            registered_tokens = [row[0] for row in cur.fetchall()]
            
            detected_tokens = set()
            
            for token in registered_tokens:
                mask = leak_df.astype(str).apply(lambda col: col.str.contains(token, case=False, na=False))
                if mask.any().any():
                    detected_tokens.add(token)
            
            if detected_tokens:
                st.error("🚨 BREACH CONFIRMED: CANARY TOKENS DETECTED IN LEAKED FILE!")
                for token in detected_tokens:
                    cur.execute("SELECT canary_id, issued_to, export_purpose, timestamp FROM canary_registry WHERE canary_id = ?", (token,))
                    match = cur.fetchone()
                    if match:
                        st.markdown(f"""
                        ---
                        ### 🔍 Attribution Verdict
                        * **Canary Token:** `{match[0]}`
                        * **Leaked By / Assigned To:** **{match[1]}**
                        * **Export Justification:** *{match[2]}*
                        * **Timestamp of Export:** `{match[3]}`
                        ---
                        """)
            else:
                st.success("✅ Clean Dataset: No registered canary tokens found across any columns.")
            conn.close()
            
        except Exception as e:
            st.error(f"Error scanning file: {e}")
# last tab
with tabs[3]:
    st.subheader("Global Canary Registry")
    conn = get_db()
    reg_df = pd.read_sql("SELECT * FROM canary_registry ORDER BY timestamp DESC", conn)
    conn.close()
    st.dataframe(reg_df, use_container_width=True)