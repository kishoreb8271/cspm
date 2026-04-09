with active_tab[6]:
        st.header("🛡️ Data Security Posture Management")
        
        # --- Real-Time Scan Logic for DSPM ---
        col_scan, col_status = st.columns([1, 1])
        with col_scan:
            if st.button("Manual DSPM Scan", type="secondary"):
                run_real_time_scan("DSPM")
            
            rt_toggle = st.toggle("Enable Real-Time Data Discovery", value=False, help="Continuously monitors S3, RDS, and Redshift for sensitive data leaks.")
            
        with col_status:
            status_container = st.empty()
            if rt_toggle:
                status_container.markdown("🟢 **Status:** Monitoring Live Data Streams...")
                # Logic to trigger automated scan refresh
                if st.session_state['integrations']:
                    # We run the scan logic silently in the background when RT is enabled
                    run_real_time_scan("Real-Time DSPM")
                    st.toast("Real-time scan completed. Findings updated.", icon="🔍")
                    time.sleep(2) # Prevent rapid-fire API calls
                else:
                    st.warning("Connect a provider to start real-time discovery.")
            else:
                status_container.markdown("⚪ **Status:** Real-time monitoring paused.")

        st.divider()
        st.subheader("Sensitive Data Findings")
        
        # Show findings dynamically
        if not st.session_state['dspm_results'].empty:
            st.dataframe(st.session_state['dspm_results'], use_container_width=True)
        else:
            st.info("No sensitive data findings detected yet. Start a scan or enable real-time monitoring.")
