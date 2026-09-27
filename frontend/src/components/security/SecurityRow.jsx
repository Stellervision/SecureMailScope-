function SecurityRow({
  label,
  value,
  positive = false,
}) {
  return (
    <div className="security-row">
      <span>
        {label}
      </span>

      <span
        className={
          positive
            ? "positive"
            : "neutral"
        }
      >
        {value}
      </span>
    </div>
  );
}

export default SecurityRow;