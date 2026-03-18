<?php

namespace Filament\Jetstream\TwoFactor\Pages;

use DanHarrin\LivewireRateLimiting\Exceptions\TooManyRequestsException;
use Filament\Actions\Action;
use Filament\Facades\Filament;
use Filament\Forms\Components\TextInput;
use Filament\Jetstream\Turnstile\ValidatesTurnstile;
use Filament\Jetstream\TwoFactor\Events\TwoFactorAuthenticationChallenged;
use Filament\Jetstream\TwoFactor\Events\TwoFactorAuthenticationFailed;
use Filament\Jetstream\TwoFactor\Events\ValidTwoFactorAuthenticationCodeProvided;
use Filament\Jetstream\TwoFactor\TwoFactorAuthenticationProvider;
use Filament\Schemas\Schema;
use Illuminate\Contracts\Support\Htmlable;
use Illuminate\Validation\ValidationException;

class Challenge extends BaseSimplePage
{
    use ValidatesTurnstile;

    protected string $view = 'filament-team-guard::pages.auth.challenge';

    public ?array $data = [];

    public ?string $turnstileResponse = null;

    public function getTitle(): string | Htmlable
    {
        return __('filament-team-guard::two_factor.pages.challenge.title');
    }

    public function mount(): void
    {
        if (! Filament::auth()->check()) {
            redirect()->to(filament()->getCurrentOrDefaultPanel()?->getLoginUrl());

            return;
        }

        $user = Filament::auth()->user();

        $this->form->fill();

        TwoFactorAuthenticationChallenged::dispatch($user);
    }

    public function recoveryAction(): Action
    {
        return Action::make('recovery')
            ->link()
            ->label(__('filament-team-guard::two_factor.pages.challenge.action_label'))
            ->url(filament()->getCurrentOrDefaultPanel()->route('two-factor.recovery'));
    }

    public function authenticate(?string $turnstileToken = null): ?\Symfony\Component\HttpFoundation\Response
    {
        try {
            $this->validateTurnstile($turnstileToken);
            $this->rateLimit(5);

            $this->form->getState();

            $user = Filament::auth()->user();

            $user->setTwoFactorChallengePassed();

            event(new ValidTwoFactorAuthenticationCodeProvided($user));

            $this->redirectIntended(filament()->getCurrentOrDefaultPanel()->getUrl());

            return null;
        } catch (TooManyRequestsException $exception) {
            $this->getRateLimitedNotification($exception)?->send();

            return null;
        }
    }

    protected function onValidationError(ValidationException $exception): void
    {
        $this->dispatchTurnstileReset();

        parent::onValidationError($exception);
    }

    public function form(Schema $schema): Schema
    {
        return $schema
            ->schema([
                TextInput::make('code')
                    ->hiddenLabel()
                    ->hint(__('filament-team-guard::default.form.code.hint'))
                    ->label(__('filament-team-guard::default.form.code.label'))
                    ->autofocus()
                    ->required()
                    ->autocomplete(false)
                    ->rules([
                        fn () => function (string $attribute, $value, $fail): void {
                            $user = Filament::auth()->user();

                            if (is_null($user)) {
                                $fail(__('filament-team-guard::two_factor.pages.challenge.error'));

                                redirect()->to(filament()->getCurrentOrDefaultPanel()->getLoginUrl());

                                return;
                            }

                            $isValidCode = app(TwoFactorAuthenticationProvider::class)->verify(
                                secret: decrypt($user->two_factor_secret),
                                code: $value,
                            );

                            if (! $isValidCode) {
                                $fail(__('filament-team-guard::two_factor.pages.challenge.error'));

                                event(new TwoFactorAuthenticationFailed($user));
                            }
                        },
                    ]),
            ])
            ->statePath('data');
    }

    public function getFormActions(): array
    {
        return [
            $this->getAuthenticateFormAction(),
        ];
    }

    protected function getAuthenticateFormAction(): Action
    {
        return Action::make('authenticate')
            ->label(__('filament-panels::auth/pages/login.form.actions.authenticate.label'))
            ->submit('authenticate');
    }

    protected function hasFullWidthFormActions(): bool
    {
        return true;
    }
}
