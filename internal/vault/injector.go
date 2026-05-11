package vault

import (
	"fmt"
)

type InjectedEnv map[string]string

type Injector struct {
	store *Store
}

func NewInjector(store *Store) *Injector {
	return &Injector{store: store}
}

func (inj *Injector) InjectForAgent(credentialsNames []string) (InjectedEnv, error) {
	env := make(InjectedEnv)

	var missing []string
	for _, name := range credentialsNames {
		value, err := inj.store.Get(name)
		if err != nil {
			missing = append(missing, name)
			continue
		}
		env[name] = value
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("credentials not found in vault: %v\n"+
				"  Add them with: agentbox vault add <NAME>",
			missing)
	}
	return env, nil
}

func (env InjectedEnv) ToSlice() []string {
	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}