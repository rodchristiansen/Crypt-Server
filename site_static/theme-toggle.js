/**
 * Theme Toggle Script for Crypt Server
 *
 * Handles dark/light mode switching with:
 * - Automatic system preference detection (prefers-color-scheme)
 * - Manual override with toggle button
 * - localStorage persistence of user preference
 * - "Auto" mode that follows system preference
 */
(function() {
    'use strict';

    const THEME_KEY = 'crypt-theme';

    /**
     * Get system preference
     */
    function getSystemTheme() {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    /**
     * Get effective theme (what should be displayed)
     */
    function getEffectiveTheme() {
        const stored = localStorage.getItem(THEME_KEY);
        if (stored === 'auto' || stored === null) {
            return getSystemTheme();
        }
        return stored;
    }

    /**
     * Get stored preference (auto, light, or dark)
     */
    function getStoredPreference() {
        return localStorage.getItem(THEME_KEY) || 'auto';
    }

    /**
     * Apply theme to document
     */
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        updateToggleButton();
    }

    /**
     * Update toggle button icon and label
     */
    function updateToggleButton() {
        const toggleBtn = document.querySelector('.theme-toggle');
        if (!toggleBtn) return;

        const preference = getStoredPreference();
        const effective = getEffectiveTheme();

        // Update aria-label based on current state
        let label;
        if (preference === 'auto') {
            label = 'Theme: Auto (following system). Click to switch to ' + 
                    (effective === 'dark' ? 'light' : 'dark') + ' mode';
        } else {
            label = 'Theme: ' + preference + '. Click to switch to auto mode';
        }
        toggleBtn.setAttribute('aria-label', label);

        // Update visual indicator for auto mode
        toggleBtn.classList.toggle('auto-mode', preference === 'auto');
    }

    /**
     * Cycle through themes: auto -> light -> dark -> auto
     */
    function toggleTheme() {
        const current = getStoredPreference();
        let next;

        if (current === 'auto') {
            // If auto and showing dark, switch to light; if showing light, switch to dark
            next = getEffectiveTheme() === 'dark' ? 'light' : 'dark';
        } else if (current === 'light') {
            next = 'dark';
        } else {
            // dark -> auto
            next = 'auto';
        }

        localStorage.setItem(THEME_KEY, next);
        applyTheme(getEffectiveTheme());
    }

    // Apply theme immediately to prevent flash
    applyTheme(getEffectiveTheme());

    // Listen for system preference changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
        // Only auto-switch if user preference is 'auto'
        if (getStoredPreference() === 'auto') {
            applyTheme(e.matches ? 'dark' : 'light');
        }
    });

    // Initialize toggle button when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        const toggleBtn = document.querySelector('.theme-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', toggleTheme);
            updateToggleButton();
        }
    });

    // Expose toggle function globally
    window.toggleTheme = toggleTheme;
})();
