import React from "react";

export default ({ result }) => (
    <li className="sui-result">
      <div className="sui-result__header">
        <span
          className="sui-result__title"
          
          dangerouslySetInnerHTML={{ __html: result.name.raw }}
        />
      </div>
    <div className="sui-result__body">
    <ul className="sui-result__details">
        <li>
            <span className="sui-result__key">Name</span>{ }
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.name.raw
              }}
            />
        </li>
        <li>
            <span className="sui-result__key">Id</span>{" "}
            <span className="sui-result__value">{result.id.raw}</span>
        </li>
        <li>
            <span className="sui-result__key">Brief</span>{ }
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.brief.raw
              }}
            />
        </li>
        <li>
            <span className="sui-result__key">Components</span>{" "}
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.components.raw
              }}
            />
        </li>
        <li>
            <span className="sui-result__key">Tier</span>{" "}
            <span className="sui-result__value">{result.tier.raw}</span>
        </li>
        <li>
            <span className="sui-result__key">Os_platform</span>{" "}
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.os_platform.raw
              }}
            />
        </li>
        <li>
            <span className="sui-result__key">Os_version</span>{" "}
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.os_version.raw
              }}
            />
        </li>
        <li>
            <span className="sui-result__key">Daemons</span>{" "}
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.daemons.raw
              }}
            />
          </li>
          <li>
            <span className="sui-result__key">Type</span>{" "}
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.type.raw
              }}
            />
          </li>
          <li>
            <span className="sui-result__key">Modules</span>{" "}
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.modules.raw
              }}
            />
          </li>
          <li>
            <span className="sui-result__key">Tests</span>{" "}
            <span
              className="sui-result__value"
              dangerouslySetInnerHTML={{
                __html: result.tests.raw
              }}
            />
          </li>
        </ul>
      </div>
    </li>
  );
  