"""Review 2 E5: per-device Argon2id calibration for new vaults."""
from vault.crypto import (ARGON2_DEFAULT_MEMORY, ARGON2_DEFAULT_TIME, calibrate_argon2_parameters,
                          create_vault_header, unlock_dek_with_password)


def linear_timer(ms_per_iteration_per_mib):
    def measure(m, t, p):
        return ms_per_iteration_per_mib * t * (m / 1024)
    return measure


def test_fast_host_reaches_target_with_256_mib():
    # 256 MiB, t=3 takes 108 ms (as measured on the development host): expect t=9.
    kdf = calibrate_argon2_parameters(measure=linear_timer(108 / 3 / 256))
    assert kdf["m"] == 262144 and kdf["t"] == 9
    assert 300 <= kdf["measured_ms"] <= 600


def test_undershooting_estimate_is_corrected_upwards():
    # Fixed start-up cost makes t=3 look relatively slow, so the linear estimate undershoots.
    def measure(m, t, p):
        return 60.0 + 25.0 * t
    kdf = calibrate_argon2_parameters(measure=measure)
    assert kdf["measured_ms"] >= 300 and measure(kdf["m"], kdf["t"] - 1, 4) < 300


def test_slow_host_falls_back_but_never_below_previous_default():
    kdf = calibrate_argon2_parameters(measure=linear_timer(4.0))  # 256 MiB, t=3 -> 3072 ms
    assert kdf["m"] == ARGON2_DEFAULT_MEMORY and kdf["t"] == ARGON2_DEFAULT_TIME


def test_very_fast_host_is_capped():
    kdf = calibrate_argon2_parameters(measure=linear_timer(1e-6))
    assert kdf["t"] == 64 and kdf["m"] == 262144


def test_calibrated_parameters_are_stored_and_unlock(tmp_path):
    kdf = calibrate_argon2_parameters(target_ms=(20.0, 40.0))  # real timing, small target
    header, dek, _ = create_vault_header("FictionalMasterPassword123!", m=kdf["m"], t=kdf["t"], p=kdf["p"])
    assert header.argon2 == {"m": kdf["m"], "t": kdf["t"], "p": kdf["p"]}
    assert unlock_dek_with_password(header, "FictionalMasterPassword123!") == dek
    assert kdf["t"] >= ARGON2_DEFAULT_TIME and kdf["m"] >= ARGON2_DEFAULT_MEMORY
