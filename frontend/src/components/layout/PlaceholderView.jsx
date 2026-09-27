function PlaceholderView({
  eyebrow,
  title,
  description,
}) {
  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">
            {eyebrow}
          </span>

          <h2>
            {title}
          </h2>

          <p>
            {description}
          </p>
        </div>
      </section>

      <section className="placeholder-card">
        <div className="shield">
          ⌁
        </div>

        <h3>
          Workspace ready
        </h3>

        <p>
          This section will connect to
          the SecureMailScope
          intelligence layer as we
          build the next feature.
        </p>
      </section>
    </>
  );
}

export default PlaceholderView;