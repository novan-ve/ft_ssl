/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_prints.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <novan-ve@student.codam.nl>         +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/12/17 16:52:41 by novan-ve      #+#    #+#                 */
/*   Updated: 2022/05/25 16:05:10 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_prints5(t_print *p)
{
	int		i;
	char	n[7];

	i = 0;
	n[0] = '(';
	n[1] = 'n';
	n[2] = 'u';
	n[3] = 'l';
	n[4] = 'l';
	n[5] = ')';
	n[6] = '\0';
	while (i < p->prec && i < 6)
	{
		p->len++;
		ft_putchar_fd(n[i], p->fd);
		i++;
	}
}

void	ft_prints4(t_print *p)
{
	int		i;

	i = 0;
	if (p->prec == -1 || p->prec > 5)
		p->tmplen = 6;
	if (p->just == 'r' && (p->prec == -1 || p->prec > 5))
		ft_putstr_fd("(null)", p->fd);
	if (p->prec < 6 && p->just == 'r')
		ft_prints5(p);
	if (p->prec > 0 && p->prec < 6)
		i = 1;
	while (i < (p->tmpwidth) && i < (p->tmpwidth - p->tmplen))
	{
		ft_putchar_fd(p->padchar, p->fd);
		i++;
	}
	if (p->prec < 6 && p->just == 'l')
		ft_prints5(p);
	if (p->just == 'l' && (p->prec == -1 || p->prec > 5))
		ft_putstr_fd("(null)", p->fd);
}

void	ft_prints3(t_print *p)
{
	int		i;

	i = 0;
	if (p->prec == p->tmpwidth && p->prec > p->tmplen)
		p->prec = p->tmplen;
	else if (p->prec == p->tmpwidth)
		p->tmplen = p->prec;
	if (p->prec > p->tmplen)
		p->prec = p->tmplen;
	if (p->just == 'r')
		ft_putprec_fd(p->strtmp, p->fd, p->prec);
	while (i < (p->tmpwidth - p->prec))
	{
		ft_putchar_fd(p->padchar, p->fd);
		i++;
	}
	if (p->just == 'l')
		ft_putprec_fd(p->strtmp, p->fd, p->prec);
	if (p->prec < p->tmplen)
		p->tmplen = p->prec;
	if (p->tmplen < p->tmpwidth)
		p->tmplen = p->tmpwidth;
}

void	ft_prints2(t_print *p)
{
	int		i;

	i = 0;
	if (p->just == 'r')
		ft_putstr_fd(p->strtmp, p->fd);
	while (i < (p->tmpwidth - p->tmplen))
	{
		ft_putchar_fd(p->padchar, p->fd);
		i++;
	}
	if (p->just == 'l')
		ft_putstr_fd(p->strtmp, p->fd);
	if (p->tmplen < p->tmpwidth)
		p->tmplen = p->tmpwidth;
}

void	ft_prints(t_print *p)
{
	int		i;

	i = 0;
	p->strtmp = va_arg(p->args, char*);
	if (p->strtmp == NULL)
		i = -1;
	else
		p->tmplen = ft_strlen(p->strtmp);
	if (p->tmplen < p->tmpwidth && p->prec == -1 && i == 0)
		ft_prints2(p);
	else if (p->prec >= 0 && i == 0)
		ft_prints3(p);
	else if (p->prec == -1 && i == 0)
		ft_putstr_fd(p->strtmp, p->fd);
	else if (i == -1)
		ft_prints4(p);
}
