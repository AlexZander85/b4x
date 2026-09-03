import clsx from "clsx";
import Link from "@docusaurus/Link";
import Translate, { translate } from "@docusaurus/Translate";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import Layout from "@theme/Layout";
import HomepageFeatures from "@site/src/components/HomepageFeatures";
import styles from "./index.module.css";

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx("hero hero--primary", styles.heroBanner)}>
      <div className="container">
        <h1 className="hero__title">{siteConfig.title}</h1>
        <p className="hero__subtitle">
          <Translate id="home.subtitle">
            Packet-level censorship bypass for Linux and routers
          </Translate>
        </p>
        <p className={styles.description}>
          <Translate id="home.description">
            Web UI, automatic configuration discovery, support for routers and
            servers
          </Translate>
        </p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/intro"
          >
            <Translate id="home.cta.start">Get started</Translate>
          </Link>
          <Link
            className="button button--outline button--secondary button--lg margin-left--md"
            to="https://github.com/DanielLavrushin/b4"
          >
            <Translate id="home.cta.github">GitHub</Translate>
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home() {
  return (
    <Layout
      title={translate({ id: "home.title", message: "Documentation" })}
      description={translate({
        id: "home.meta.description",
        message: "b4 - censorship bypass for Linux",
      })}
    >
      <HomepageHeader />
      <main>
        <HomepageFeatures />
      </main>
    </Layout>
  );
}
