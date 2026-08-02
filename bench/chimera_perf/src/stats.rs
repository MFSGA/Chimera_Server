pub fn median(values: &[f64]) -> f64 {
    percentile(values, 50.0)
}

pub fn percentile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = ((percentile.clamp(0.0, 100.0) / 100.0)
        * (sorted.len().saturating_sub(1) as f64))
        .round() as usize;
    sorted[rank]
}

pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

pub fn sample_stdev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let avg = mean(values);
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - avg;
            delta * delta
        })
        .sum::<f64>()
        / (values.len() - 1) as f64;
    variance.sqrt()
}

pub fn coefficient_of_variation(values: &[f64]) -> f64 {
    let avg = mean(values);
    if avg == 0.0 {
        return 0.0;
    }
    sample_stdev(values) / avg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_handles_ordering() {
        let values = [5.0, 1.0, 4.0, 2.0, 3.0];
        assert_eq!(median(&values), 3.0);
        assert_eq!(percentile(&values, 99.0), 5.0);
    }

    #[test]
    fn coefficient_of_variation_is_zero_for_constant_values() {
        assert_eq!(coefficient_of_variation(&[10.0, 10.0, 10.0]), 0.0);
    }
}
